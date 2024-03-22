// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"log"
	"time"

	nc "aconcli/netconn"
	pb "aconcli/proto"
	"google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type AconClient struct {
	pb.AconServiceClient
	conn *grpc.ClientConn
}

func (c *AconClient) Close() error {
	return c.conn.Close()
}

type AconStatus struct {
	ContainerId uint32
	State       uint32
	Wstatus     int32
	ImageId     string
	ExePath     string
}

const (
	defaultServiceTimeout = 10 * time.Second
)

// caller's responsibility to call Close() on the returned AconClient
// after using the agent services
func NewAconConnection(targetConn string) (*AconClient, error) {
	log.Println("Service: Connecting", targetConn)
	conn, err := nc.NewConnection(targetConn)
	if err != nil {
		return nil, err
	}
	log.Println("Service: Connected")
	return &AconClient{
		AconServiceClient: pb.NewAconServiceClient(conn),
		conn:              conn,
	}, nil
}

func AddManifest(sc pb.AconServiceClient, manifest string, sig, cert []byte) (string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	r, err := sc.AddManifest(ctx,
		&pb.AddManifestRequest{Manifest: manifest,
			Signature:   sig,
			Certificate: cert,
		})
	if err != nil {
		return "", nil, err
	}
	return r.GetImageId(), r.GetMissingLayers(), nil
}

func AddBlob(sc pb.AconServiceClient, alg uint32, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	_, err := sc.AddBlob(ctx, &pb.AddBlobRequest{Alg: alg, Data: data})
	return err
}

func Finalize(sc pb.AconServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	_, err := sc.Finalize(ctx, &emptypb.Empty{})
	return err
}

func Start(sc pb.AconServiceClient, imageId string, env []string) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	r, err := sc.Start(ctx, &pb.StartRequest{ImageId: imageId, Envs: env})
	if err != nil {
		return 0, err
	}
	return r.GetContainerId(), nil
}

func Kill(sc pb.AconServiceClient, cid uint32, signum int32) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	_, err := sc.Kill(ctx, &pb.KillRequest{ContainerId: cid, SignalNum: signum})
	return err
}

func Restart(sc pb.AconServiceClient, cid uint32, timeout uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout+time.Duration(timeout)*time.Second)
	defer cancel()

	_, err := sc.Restart(ctx, &pb.RestartRequest{ContainerId: cid, Timeout: timeout})
	return err
}

func Invoke(sc pb.AconServiceClient, cid uint32, invocation []string,
	timeout uint64, env []string, data []byte, capture_size uint64) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout+time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := invocation[0]
	var args []string
	if len(invocation) > 1 {
		args = invocation[1:]
	}

	r, err := sc.Exec(ctx, &pb.ExecRequest{
		ContainerId: cid,
		Command:     cmd,
		Timeout:     timeout,
		Arguments:   args,
		Envs:        env,
		Stdin:       data,
		CaptureSize: capture_size})
	if err != nil {
		return nil, nil, err
	}
	return r.GetStdout(), r.GetStderr(), nil
}

func Inspect(sc pb.AconServiceClient, cid uint32) ([]AconStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	r, err := sc.Inspect(ctx, &pb.InspectRequest{ContainerId: cid})
	if err != nil {
		return nil, err
	}

	// cid == 0 indicates getting status for all acon instances
	// otherwise, get the status for the specified acon.
	status := r.GetInfo()
	result := make([]AconStatus, 0, len(status))
	for _, s := range status {
		result = append(result, AconStatus{ContainerId: s.GetContainerId(),
			State:   s.GetState(),
			Wstatus: s.GetWstatus(),
			ImageId: s.GetImageId(),
			ExePath: s.GetExePath()})
	}
	return result, nil
}

func Report(sc pb.AconServiceClient, nonceLo, nonceHi uint64, requestType uint32) (data []byte,
	mrlog0 []string, mrlog1 []string, mrlog2 []string, mrlog3 []string, attest_data string, e error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceTimeout)
	defer cancel()

	r, err := sc.Report(ctx, &pb.ReportRequest{NonceLo: nonceLo, NonceHi: nonceHi, RequestType: requestType})
	if err != nil {
		e = err
		return
	}
	data = r.GetData()
	mrlogs := r.GetMrlog()
	mrlog0 = mrlogs[0].GetLogs()
	mrlog1 = mrlogs[1].GetLogs()
	mrlog2 = mrlogs[2].GetLogs()
	mrlog3 = mrlogs[3].GetLogs()
	attest_data = r.GetAttestationData()
	return
}
