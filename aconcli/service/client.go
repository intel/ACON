package service

type AconStatus struct {
	ContainerId uint32 `json:"container_id"`
	State       uint32 `json:"state"`
	Wstatus     int32  `json:"wstatus"`
	ImageId     string `json:"image_id"`
	ExePath     string `json:"exe_path"`
}

type AconClient interface {
	AddManifest(manifestPath, sigPath, certPath string) (string, []string, error)
	AddBlob(alg uint32, blobpath string) error
	Finalize() error
	Start(imageId string, env []string) (uint32, error)
	Kill(cid uint32, signum int32) error
	Restart(cid uint32, timeout uint64) error
	Invoke(cid uint32, invocation []string, timeout uint64,
		env []string, datafile string, capSize uint64) ([]byte, []byte, error)
	Inspect(cid uint32) ([]AconStatus, error)
	Report(nonceLow, nonceHigh uint64, reportType uint32) (data []byte, mrlog0 []string,
		mrlog1 []string, mrlog2 []string,
		mrlog3 []string, attestData string,
		e error)
}
