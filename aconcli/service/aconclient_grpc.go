package service

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	nc "aconcli/netconn"
	pb "aconcli/proto"
	"google.golang.org/grpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

const (
	DefaultServiceTimeout = 10 * time.Second
)

type AconClientGrpc struct {
	pb.AconServiceClient
	conn *grpc.ClientConn
}

// caller's responsibility to call Close() on the returned AconClient
// after using the agent services
func NewAconGrpcConnection(targetConn string) (*AconClientGrpc, error) {
	log.Println("Service: Connecting", targetConn)
	conn, err := nc.NewConnection(targetConn)
	if err != nil {
		return nil, err
	}
	log.Println("Service: Connected")
	return &AconClientGrpc{
		AconServiceClient: pb.NewAconServiceClient(conn),
		conn:              conn,
	}, nil
}

func (c *AconClientGrpc) Close() error {
	return c.conn.Close()
}

func (c *AconClientGrpc) AddManifest(manifestPath, sigPath, certPath string) (string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	aconJSON, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", nil, err
	}

	var v interface{}
	if err := json.Unmarshal(aconJSON, &v); err != nil {
		return "", nil, err
	}
	aconJSON, err = json.Marshal(v)
	if err != nil {
		return "", nil, err
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return "", nil, err
	}

	cert, err := os.ReadFile(certPath)
	if err != nil {
		return "", nil, err
	}
	r, err := c.AconServiceClient.AddManifest(ctx,
		&pb.AddManifestRequest{Manifest: string(aconJSON),
			Signature:   sig,
			Certificate: cert,
		})
	if err != nil {
		return "", nil, err
	}
	return r.GetImageId(), r.GetMissingLayers(), nil
}

func (c *AconClientGrpc) AddBlob(alg uint32, blobpath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	content, err := os.ReadFile(filepath.Clean(blobpath))
	if err != nil {
		return err
	}
	_, err = c.AconServiceClient.AddBlob(ctx, &pb.AddBlobRequest{Alg: alg, Data: content})
	return err
}

func (c *AconClientGrpc) Finalize() error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	_, err := c.AconServiceClient.Finalize(ctx, &emptypb.Empty{})
	return err
}

func (c *AconClientGrpc) Start(imageId string, env []string) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	r, err := c.AconServiceClient.Start(ctx, &pb.StartRequest{ImageId: imageId, Envs: env})
	if err != nil {
		return 0, err
	}
	return r.GetContainerId(), nil
}

func (c *AconClientGrpc) Kill(cid uint32, signum int32) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	_, err := c.AconServiceClient.Kill(ctx, &pb.KillRequest{ContainerId: cid, SignalNum: signum})
	return err
}

func (c *AconClientGrpc) Restart(cid uint32, timeout uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout+time.Duration(timeout)*time.Second)
	defer cancel()

	_, err := c.AconServiceClient.Restart(ctx, &pb.RestartRequest{ContainerId: cid, Timeout: timeout})
	return err
}

func (c *AconClientGrpc) Invoke(cid uint32, invocation []string,
	timeout uint64, env []string, datafile string, capture_size uint64) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout+time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := invocation[0]
	var args []string
	if len(invocation) > 1 {
		args = invocation[1:]
	}

	var data []byte
	if datafile != "" {
		d, err := os.ReadFile(filepath.Clean(datafile))
		if err != nil {
			return nil, nil, err
		}
		data = d
	}

	r, err := c.AconServiceClient.Exec(ctx, &pb.ExecRequest{
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

func (c *AconClientGrpc) Inspect(cid uint32) ([]AconStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	r, err := c.AconServiceClient.Inspect(ctx, &pb.InspectRequest{ContainerId: cid})
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

func (c *AconClientGrpc) Report(nonceLo, nonceHi uint64, requestType uint32) (data []byte,
	mrlog0 []string, mrlog1 []string, mrlog2 []string, mrlog3 []string, attest_data string, e error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultServiceTimeout)
	defer cancel()

	r, err := c.AconServiceClient.Report(ctx, &pb.ReportRequest{NonceLo: nonceLo, NonceHi: nonceHi, RequestType: requestType})
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
