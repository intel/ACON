// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package netconn

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	UnixSocketScheme   = "unix"
	VSockSocketScheme  = "vsock"
	TCPSocketScheme    = "tcp"
	defaultDialTimeout = 30 * time.Second
)

func parse(sock string) (string, *url.URL, error) {
	addr, err := url.Parse(sock)
	if err != nil {
		return "", nil, err
	}

	var grpcAddr string
	switch addr.Scheme {
	case VSockSocketScheme:
		if addr.Hostname() == "" || addr.Port() == "" || addr.Path != "" {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock scheme: %s", sock)
		}
		if _, err := strconv.ParseUint(addr.Hostname(), 10, 32); err != nil {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock cid: %s", sock)
		}
		if _, err := strconv.ParseUint(addr.Port(), 10, 32); err != nil {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock port: %s", sock)
		}
		grpcAddr = VSockSocketScheme + ":" + addr.Host
	case TCPSocketScheme:
		grpcAddr = TCPSocketScheme + ":" + addr.Host
	case UnixSocketScheme:
		fallthrough
	case "":
		if (addr.Host == "" && addr.Path == "") || addr.Port() != "" {
			return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid unix scheme: %s", sock)
		}
		if addr.Host == "" {
			grpcAddr = UnixSocketScheme + ":///" + addr.Path
		} else {
			grpcAddr = UnixSocketScheme + ":///" + addr.Host + "/" + addr.Path
		}
	default:
		return "", nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid scheme: %s", sock)
	}

	return grpcAddr, addr, nil
}

type dialer func(string, time.Duration) (net.Conn, error)

func agentDialer(addr *url.URL) dialer {
	var d dialer
	switch addr.Scheme {
	case VSockSocketScheme:
		d = vsockDialer
	case TCPSocketScheme:
		d = tcpDialer
	case UnixSocketScheme:
		fallthrough
	default:
		d = unixDialer
	}
	return d
}

func unixDialer(sock string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(sock, "unix:") {
		sock = strings.Trim(sock, "unix:")
	}

	dialFunc := func() (net.Conn, error) {
		return net.DialTimeout("unix", sock, timeout)
	}

	timeoutErr := grpcStatus.Errorf(codes.DeadlineExceeded, "timed out connecting to unix socket %s", sock)
	return commonDialer(timeout, dialFunc, timeoutErr)
}

func vsockDialer(sock string, timeout time.Duration) (net.Conn, error) {
	cid, port, err := parseGrpcVsockAddr(sock)
	if err != nil {
		return nil, err
	}

	dialFunc := func() (net.Conn, error) {
		return vsock.Dial(cid, port, nil)
	}

	timeoutErr := grpcStatus.Errorf(codes.DeadlineExceeded, "timed out connecting to vsock %d:%d", cid, port)

	return commonDialer(timeout, dialFunc, timeoutErr)
}

func tcpDialer(sock string, timeout time.Duration) (net.Conn, error) {
	if !strings.HasPrefix(sock, "tcp:") {
		return nil, grpcStatus.Errorf(codes.InvalidArgument, "Invalid tcp URL scheme: %s", sock)
	}
	sock = strings.TrimPrefix(sock, "tcp:")

	dialFunc := func() (net.Conn, error) {
		return net.Dial("tcp", sock)
	}

	timeoutErr := grpcStatus.Errorf(codes.DeadlineExceeded, "timed out connecting to tcp socket %s", sock)
	return commonDialer(timeout, dialFunc, timeoutErr)
}

func commonDialer(timeout time.Duration, dialFunc func() (net.Conn, error), timeoutErrMsg error) (net.Conn, error) {
	t := time.NewTimer(timeout)
	cancel := make(chan bool)
	ch := make(chan net.Conn)
	go func() {
		for {
			select {
			case <-cancel:
				// canceled or channel closed
				return
			default:
			}

			conn, err := dialFunc()
			if err == nil {
				// Send conn back iff timer is not fired
				// Otherwise there might be no one left reading it
				if t.Stop() {
					ch <- conn
				} else {
					conn.Close()
				}
				return
			}
		}
	}()

	var conn net.Conn
	var ok bool
	select {
	case conn, ok = <-ch:
		if !ok {
			return nil, timeoutErrMsg
		}
	case <-t.C:
		cancel <- true
		return nil, timeoutErrMsg
	}

	return conn, nil
}

func parseGrpcVsockAddr(sock string) (uint32, uint32, error) {
	sp := strings.Split(sock, ":")
	if len(sp) != 3 {
		return 0, 0, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock address: %s", sock)
	}
	if sp[0] != VSockSocketScheme {
		return 0, 0, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock URL scheme: %s", sp[0])
	}

	cid, err := strconv.ParseUint(sp[1], 10, 32)
	if err != nil {
		return 0, 0, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock cid: %s", sp[1])
	}
	port, err := strconv.ParseUint(sp[2], 10, 32)
	if err != nil {
		return 0, 0, grpcStatus.Errorf(codes.InvalidArgument, "Invalid vsock port: %s", sp[2])
	}

	return uint32(cid), uint32(port), nil
}

func NewConnection(sock string) (*grpc.ClientConn, error) {
	ctx := context.Background()
	grpcAddr, parsedAddr, err := parse(sock)
	if err != nil {
		return nil, err
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		// explicitly set ':authority' pseudo header to avoid HTTP2 Protocol Error
		grpc.WithAuthority("acond"),
		grpc.WithDialer(agentDialer(parsedAddr))}

	ctx, cancel := context.WithTimeout(ctx, defaultDialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, grpcAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
