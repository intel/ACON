package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

const (
	endpointBlob     = "/api/v1/blob"
	endpointManifest = "/api/v1/manifest"
	endpointFinalize = "/api/v1/manifest/finalize"
	endpointStart    = "/api/v1/container/start"
	endpointExec     = "/api/v1/container/exec"
	endpointInspect  = "/api/v1/container/inspect"
	endpointReport   = "/api/v1/container/report"
	endpointKill     = "/api/v1/container/kill"
	endpointRestart  = "/api/v1/container/restart"

	fieldManifest  = "manifest"
	fieldSig       = "signature"
	fieldCert      = "certificate"
	fieldImgeId    = "image_id"
	fieldMissLayer = "missing_layers"
	fieldAlg       = "alg"
	fieldBlob      = "data"
	fieldEnvs      = "envs"
	fieldConId     = "container_id"
	fieldTimeout   = "timeout"
	fieldCommand   = "command"
	fieldArgs      = "arguments"
	fieldStdin     = "stdin"
	fieldCapSize   = "capture_size"
	fieldSignum    = "signal_num"
	fieldNonceLow  = "nonce_lo"
	fieldNonceHigh = "nonce_hi"
	fieldReqType   = "request_type"

	clientMakeReqErrFmt   = "%s: error make request: %s"
	clientSendReqErrFmt   = "%s: error send request: %s"
	clientProcRespErrFmt  = "%s: error read response: %s"
	clientUnmarshalErrFmt = "%s: error unmarshal response: %s"
)

type AddManifestResponse struct {
	ImageId       string   `json:"image_id"`
	MissingLayers []string `json:"missing_layers"`
}

type StartResponse struct {
	ContainerId uint32 `json:"container_id"`
}

type ExecResponse struct {
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
}

type InspectResponse struct {
	Info []AconStatus `json:"info"`
}

type MrLog struct {
	Logs []string `json:"logs"`
}

type ReportResponse struct {
	Data            []byte           `json:"data"`
	Mrlogs          map[uint32]MrLog `json:"mrlog"`
	AttestationData string           `json:"attestationData"`
}

type GetManifestResponse struct {
	Manifest    string `json:"manifest"`
	Certificate []byte `json:"certificate"`
}

type AconClientHttp struct {
	*http.Client
	Host   string
	UseTLS bool
}

func customizedVC(s tls.ConnectionState) error {
	fmt.Println("checking connection state ...")
	// TODO: add customized checks here
	fmt.Println("check pass")
	return nil
}

func NewAconHttpConnection(host string, useTLS bool) (*AconClientHttp, error) {
	log.Println("Service: Connecting", host)
	var client *http.Client
	if useTLS {
		tr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, addr, &tls.Config{
					InsecureSkipVerify: true,
					VerifyConnection:   customizedVC,
				})
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   defaultServiceTimeout,
		}
	} else {
		client = &http.Client{
			Timeout: defaultServiceTimeout,
		}
	}
	return &AconClientHttp{
		client,
		host,
		useTLS,
	}, nil
}

func processReponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	log.Println("status:", resp.Status)
	if resp.StatusCode == http.StatusInternalServerError {
		return nil, fmt.Errorf("internal error")
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("bad request")
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read reponse body error: %s", err)
	}
	return respBody, nil
}

func (c *AconClientHttp) makeURL(endpoint string) string {
	scheme := "http"
	if c.UseTLS {
		scheme = "https"
	}
	return scheme + "://" + c.Host + endpoint
}

func multipartFile(w *multipart.Writer, fieldname, filename string) error {
	f, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	fw, err := w.CreateFormFile(fieldname, fi.Name())
	if err != nil {
		return err
	}
	_, err = io.Copy(fw, f)
	return err
}

func multipartManifestField(w *multipart.Writer, fieldname, filename string) error {
	f, err := os.Open(filepath.Clean(filename))
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	aconJSON := make([]byte, fi.Size())
	_, err = f.Read(aconJSON)
	if err != nil {
		return err
	}

	var v interface{}
	if err := json.Unmarshal(aconJSON, &v); err != nil {
		return err
	}
	aconJSON, err = json.Marshal(v)
	if err != nil {
		return err
	}
	fw, err := w.CreateFormFile(fieldname, fi.Name())
	if err != nil {
		return err
	}
	_, err = fw.Write(aconJSON)
	return err
}

func (c *AconClientHttp) AddManifest(manifest, sig, cert string) (string, []string, error) {
	requestURL := c.makeURL(endpointManifest)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	if err := multipartManifestField(w, "manifest", manifest); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	if err := multipartFile(w, "sig", sig); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	if err := multipartFile(w, "cert", cert); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return "", nil, fmt.Errorf(clientMakeReqErrFmt, "AddManifest", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf(clientSendReqErrFmt, "AddManifest", err)
	}
	content, err := processReponse(resp)
	if err != nil {
		return "", nil, fmt.Errorf(clientProcRespErrFmt, "AddManifest", err)
	}
	r := AddManifestResponse{}
	if err = json.Unmarshal(content, &r); err != nil {
		return "", nil, fmt.Errorf(clientUnmarshalErrFmt, "AddManifest", err)
	}
	return r.ImageId, r.MissingLayers, nil
}

func (c *AconClientHttp) AddBlob(alg uint32, blobpath string) error {
	blobpath = filepath.Clean(blobpath)
	requestURL := fmt.Sprintf("%s/%s?%s=%s", c.makeURL(endpointBlob),
		filepath.Base(blobpath), fieldAlg, strconv.FormatUint(uint64(alg), 10))
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	if err := multipartFile(w, fieldBlob, blobpath); err != nil {
		return fmt.Errorf("AddBlob, prepare multipart error: %s", err)
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPut, requestURL, body)
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "AddBlob", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf(clientSendReqErrFmt, "AddBlob", err)
	}
	if _, err = processReponse(resp); err != nil {
		return fmt.Errorf(clientProcRespErrFmt, "AddBlob", err)
	} else {
		return nil
	}
}

func (c *AconClientHttp) Finalize() error {
	requestURL := c.makeURL(endpointFinalize)
	req, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "Finalize", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf(clientSendReqErrFmt, "Finalize", err)
	}
	if _, err = processReponse(resp); err != nil {
		return fmt.Errorf(clientProcRespErrFmt, "Finalize", err)
	} else {
		return nil
	}
}

func (c *AconClientHttp) Start(imageId string, env []string) (uint32, error) {
	requestURL := c.makeURL(endpointStart)
	d := url.Values{}
	d.Set(fieldImgeId, imageId)
	for _, e := range env {
		d.Add(fieldEnvs, e)
	}

	resp, err := c.PostForm(requestURL, d)
	if err != nil {
		return 0, fmt.Errorf(clientSendReqErrFmt, "Start", err)
	}
	content, err := processReponse(resp)
	if err != nil {
		return 0, fmt.Errorf(clientProcRespErrFmt, "Start", err)
	}
	r := StartResponse{}
	if err = json.Unmarshal(content, &r); err != nil {
		return 0, fmt.Errorf(clientUnmarshalErrFmt, "Start", err)
	}
	return r.ContainerId, nil
}

func (c *AconClientHttp) Kill(cid uint32, signum int32) error {
	requestURL := c.makeURL(endpointKill)
	d := url.Values{}
	d.Set(fieldConId, strconv.FormatUint(uint64(cid), 10))
	d.Set(fieldSignum, strconv.FormatInt(int64(signum), 10))

	resp, err := c.PostForm(requestURL, d)
	if err != nil {
		return fmt.Errorf(clientSendReqErrFmt, "Kill", err)
	}
	if _, err = processReponse(resp); err != nil {
		return fmt.Errorf(clientProcRespErrFmt, "Kill", err)
	} else {
		return nil
	}
}

func (c *AconClientHttp) Restart(cid uint32, timeout uint64) error {
	requestURL := c.makeURL(endpointRestart)
	d := url.Values{}
	d.Set(fieldConId, strconv.FormatUint(uint64(cid), 10))
	d.Set(fieldTimeout, strconv.FormatUint(timeout, 10))

	resp, err := c.PostForm(requestURL, d)
	if err != nil {
		return fmt.Errorf(clientSendReqErrFmt, "Restart", err)
	}
	if _, err = processReponse(resp); err != nil {
		return fmt.Errorf(clientProcRespErrFmt, "Restart", err)
	} else {
		return nil
	}
}

func (c *AconClientHttp) Invoke(cid uint32, invocation []string,
	timeout uint64, env []string, datafile string, capture_size uint64) ([]byte, []byte, error) {
	requestURL := c.makeURL(endpointExec)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	if datafile != "" {
		if err := multipartFile(w, fieldStdin, datafile); err != nil {
			return nil, nil, fmt.Errorf("Invoke, prepare multipart error: %s", err)
		}
	}
	w.WriteField(fieldConId, strconv.FormatUint(uint64(cid), 10))
	w.WriteField(fieldTimeout, strconv.FormatUint(timeout, 10))
	w.WriteField(fieldCapSize, strconv.FormatUint(capture_size, 10))
	for _, arg := range invocation {
		w.WriteField(fieldCommand, arg)
	}
	for _, e := range env {
		w.WriteField(fieldEnvs, e)
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return nil, nil, fmt.Errorf(clientMakeReqErrFmt, "Invoke", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf(clientSendReqErrFmt, "Invoke", err)
	}
	content, err := processReponse(resp)
	if err != nil {
		return nil, nil, fmt.Errorf(clientProcRespErrFmt, "Invoke", err)
	}
	r := ExecResponse{}
	if err = json.Unmarshal(content, &r); err != nil {
		return nil, nil, fmt.Errorf(clientUnmarshalErrFmt, "Invoke", err)
	} else {
		return r.Stdout, r.Stderr, nil
	}
}

func (c *AconClientHttp) Inspect(cid uint32) ([]AconStatus, error) {
	requestURL := fmt.Sprintf("%s?%s=%s", c.makeURL(endpointInspect),
		fieldConId, strconv.FormatUint(uint64(cid), 10))
	resp, err := c.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf(clientSendReqErrFmt, "Inspect", err)
	}
	content, err := processReponse(resp)
	if err != nil {
		return nil, fmt.Errorf(clientProcRespErrFmt, "Inspect", err)
	}
	r := InspectResponse{}
	if err = json.Unmarshal(content, &r); err != nil {
		return nil, fmt.Errorf(clientUnmarshalErrFmt, "Inspect", err)
	} else {
		return r.Info, nil
	}
}

func (c *AconClientHttp) Report(nonceLo, nonceHi uint64, reqType uint32) (data []byte,
	mrlog0 []string, mrlog1 []string, mrlog2 []string, mrlog3 []string, attest_data string, e error) {
	requestURL := fmt.Sprintf("%s?%s=%s&%s=%s&%s=%s", c.makeURL(endpointReport),
		fieldNonceLow, strconv.FormatUint(nonceLo, 10),
		fieldNonceHigh, strconv.FormatUint(nonceHi, 10),
		fieldReqType, strconv.FormatUint(uint64(reqType), 10))
	resp, err := c.Get(requestURL)
	if err != nil {
		e = fmt.Errorf(clientSendReqErrFmt, "Report", err)
		return
	}
	content, err := processReponse(resp)
	if err != nil {
		e = fmt.Errorf(clientProcRespErrFmt, "Report", err)
		return
	}
	r := ReportResponse{}
	if err = json.Unmarshal(content, r); err != nil {
		e = fmt.Errorf(clientUnmarshalErrFmt, "Report", err)
		return
	} else {
		data = r.Data
		mrlog0 = r.Mrlogs[0].Logs
		mrlog1 = r.Mrlogs[1].Logs
		mrlog2 = r.Mrlogs[2].Logs
		mrlog3 = r.Mrlogs[3].Logs
		attest_data = r.AttestationData
		return
	}
}
