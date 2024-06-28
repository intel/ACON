package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aconcli/config"
	"aconcli/cryptoutil"
)

const (
	endpointBlob     = "/api/v1/blob/%s?%s=%d"
	endpointLogin    = "/api/v1/oauth2/login"
	endpointLogout   = "/api/v1/oauth2/logout"
	endpointManifest = "/api/v1/manifest"
	endpointFinalize = "/api/v1/manifest/finalize"
	endpointStart    = "/api/v1/container/start?%s"
	endpointExec     = "/api/v1/container/%d/exec?%s"
	endpointInspect  = "/api/v1/container/%d/inspect"
	endpointReport   = "/api/v1/container/report?%s"
	endpointKill     = "/api/v1/container/%d/kill"
	endpointRestart  = "/api/v1/container/%d/restart?%s"

	fieldManifest  = "manifest"
	fieldSig       = "sig"
	fieldCert      = "cert"
	fieldImgeId    = "image_id"
	fieldMissLayer = "missing_layers"
	fieldAlg       = "alg"
	fieldBlob      = "data"
	fieldEnvs      = "env"
	fieldTimeout   = "timeout"
	fieldCommand   = "cmd"
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
	clientLoginErrFmt     = "%s: error login: %s"

	CONFIG_URL_GOOGLE = "https://accounts.google.com/.well-known/openid-configuration"
)

type AuthCode struct {
	DeviceCode      string `json:"device_code"`
	Expiration      uint   `json:"expires_in"`
	Interval        uint   `json:"interval"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
}

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

type OpenidConfig struct {
	DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
}

type AconClientHttp struct {
	client      *http.Client
	host        string
	scheme      string
	noAuth      bool
	sessionkey  string
	fingerPrint string
}

type Opt func(*AconClientHttp) error

func OptNoAuth() Opt {
	return func(c *AconClientHttp) error {
		c.noAuth = true
		return nil
	}
}

func OptTimeout(timeout time.Duration) Opt {
	return func(c *AconClientHttp) error {
		c.client.Timeout = timeout
		return nil
	}
}

func OptDialTLSContextInsecure() Opt {
	return func(c *AconClientHttp) error {
		tr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, addr, &tls.Config{
					InsecureSkipVerify: true,
					VerifyConnection: func(tcs tls.ConnectionState) error {
						digest, err := cryptoutil.BytesDigest(tcs.PeerCertificates[0].RawSubjectPublicKeyInfo, "sha384")
						if err != nil {
							return fmt.Errorf("failed to digest server's public key info: %v", err)
						}
						c.fingerPrint = hex.EncodeToString(digest)
						return nil
					},
				})
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
		c.client.Transport = tr
		c.scheme = "https"
		return nil
	}
}

func OptDialTLSContext(caCertFilePath string) Opt {
	return func(c *AconClientHttp) error {
		certPool := x509.NewCertPool()
		if caCertPEM, err := os.ReadFile(caCertFilePath); err != nil {
			return err
		} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
			return fmt.Errorf("invalid cert in CA cert file")
		}
		tr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, addr, &tls.Config{RootCAs: certPool})
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
		c.client.Transport = tr
		c.scheme = "https"
		return nil
	}
}
func NewAconHttpConnWithOpts(host string, opts ...Opt) (*AconClientHttp, error) {
	log.Println("Service: Connecting", host)
	c := &AconClientHttp{&http.Client{Timeout: DefaultServiceTimeout}, host, "http", false, "", ""}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func processReponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status: %s", resp.Status)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read reponse body error: %s", err)
	}
	return respBody, nil
}

func (c *AconClientHttp) makeURL(endpoint string, params ...any) string {
	return fmt.Sprintf(c.scheme+"://"+c.host+endpoint, params...)
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

func (c *AconClientHttp) tlsHandShake() error {
	conn, err := tls.Dial("tcp", c.host, &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(tcs tls.ConnectionState) error {
			digest, err := cryptoutil.BytesDigest(tcs.PeerCertificates[0].RawSubjectPublicKeyInfo, "sha384")
			if err != nil {
				return fmt.Errorf("failed to digest server's public key info: %v", err)
			}
			c.fingerPrint = hex.EncodeToString(digest)
			return nil
		},
	})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (c *AconClientHttp) fetchSessionKey() error {
	if len(c.sessionkey) > 0 {
		return nil
	}
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}
	key, err := GetAuthToken(user.Uid, c.fingerPrint)
	if err != nil {
		return err
	}
	c.sessionkey = key
	return nil
}

func (c *AconClientHttp) setRequestAuthHeader(req *http.Request) error {
	if c.noAuth {
		return nil
	}
	if err := c.fetchSessionKey(); err != nil {
		return fmt.Errorf("failed to get auth token: %v", err)
	}
	req.Header.Add("Authorization", c.sessionkey)
	return nil
}

func (c *AconClientHttp) Logout(uid string) error {
	if err := c.tlsHandShake(); err != nil {
		return err
	}
	sessionkey, loggedIn := IsLoggedIn(uid, c.fingerPrint)
	if !loggedIn {
		return nil
	}
	requestURL := c.makeURL(endpointLogout)
	req, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "Logout", err)
	}
	req.Header.Add("Authorization", sessionkey)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf(clientSendReqErrFmt, "Logout", err)
	}
	if _, err = processReponse(resp); err != nil {
		return fmt.Errorf(clientProcRespErrFmt, "Logout", err)
	}

	if err := RemoveAuthToken(uid, c.fingerPrint); err != nil {
		return fmt.Errorf("failed to log out: %v", err)
	}
	return nil
}

func (c *AconClientHttp) Login(uid string) error {
	clientId := os.Getenv("ATD_CLIENT_ID")
	if clientId == "" {
		return fmt.Errorf("failed to get env variable ATD_CLIENT_ID for authentication")
	}
	clientSec := os.Getenv("ATD_CLIENT_SECRET")
	if clientSec == "" {
		return fmt.Errorf("failed to get env variable ATD_CLIENT_SECRET for authentication")
	}
	resp, err := http.Get(CONFIG_URL_GOOGLE)
	if err != nil {
		return fmt.Errorf("failed to get openid config: %v", err)
	}
	configJson, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read openid config: %v", err)
	}
	var oidConfig OpenidConfig
	if err := json.Unmarshal(configJson, &oidConfig); err != nil {
		return fmt.Errorf("failed to extract openid config: %v", err)
	}

	authEndpoint := oidConfig.DeviceAuthEndpoint
	resp, err = http.PostForm(authEndpoint,
		url.Values{
			"client_id": {clientId},
			"scope":     {"email"}})
	if err != nil {
		return fmt.Errorf("failed to get response from auth server (%s): %v",
			authEndpoint, err)
	}
	defer resp.Body.Close()
	authCodeJson, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from auth server (%s): %v",
			authEndpoint, err)
	}
	var auth AuthCode
	if err := json.Unmarshal(authCodeJson, &auth); err != nil {
		return fmt.Errorf("failed to extract auth code info: %v", err)
	}
	fmt.Printf("\nTo obtain the access token, please visit the following URL via a web browser:\n\n%s\n\n"+
		"and fill in the following code:\n\n%s\n\n", auth.VerificationURL, auth.UserCode)

	resp, err = c.client.PostForm(c.makeURL(endpointLogin),
		url.Values{
			"client_id":     {clientId},
			"client_secret": {clientSec},
			"device_code":   {auth.DeviceCode},
			"expires_in":    {strconv.FormatUint(uint64(auth.Expiration), 10)},
			"interval":      {strconv.FormatUint(uint64(auth.Interval), 10)}})
	if err != nil {
		return fmt.Errorf("failed to get access token: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("\nFingerprint of ACON-TD being connected: %s\n",
		c.fingerPrint[0:config.ShortHashLen])
	keydata, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response for access token: %v", err)
	}
	var key string
	if err := json.Unmarshal(keydata, &key); err != nil {
		return fmt.Errorf("failed to parse access token from response: %v", err)
	}
	if err := UpdateAuthToken(uid, map[string]string{c.fingerPrint: key}); err != nil {
		return fmt.Errorf("failed to update access token: %v", err)
	}
	c.sessionkey = key
	return nil
}

func (c *AconClientHttp) AddManifest(manifest, sig, cert string) (string, []string, error) {
	requestURL := c.makeURL(endpointManifest)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	if err := multipartManifestField(w, fieldManifest, manifest); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	if err := multipartFile(w, fieldSig, sig); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	if err := multipartFile(w, fieldCert, cert); err != nil {
		return "", nil, fmt.Errorf("AddManifest, prepare multipart error: %s", err)
	}
	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return "", nil, fmt.Errorf(clientMakeReqErrFmt, "AddManifest", err)
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		return "", nil, fmt.Errorf(clientLoginErrFmt, "AddManifest", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.client.Do(req)
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
	requestURL := c.makeURL(endpointBlob, filepath.Base(blobpath), fieldAlg, alg)

	f, err := os.Open(blobpath)
	if err != nil {
		return fmt.Errorf("AddBlob, error open blob file: %s", err)
	}
	defer f.Close()

	req, err := http.NewRequest(http.MethodPut, requestURL, f)
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "AddBlob", err)
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		return fmt.Errorf(clientLoginErrFmt, "AddBlob", err)
	}

	resp, err := c.client.Do(req)
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

	if err := c.setRequestAuthHeader(req); err != nil {
		return fmt.Errorf(clientLoginErrFmt, "Finalize", err)
	}

	resp, err := c.client.Do(req)
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
	d := url.Values{}
	d.Set(fieldImgeId, imageId)
	requestURL := c.makeURL(endpointStart, d.Encode())

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	w.WriteField(fieldEnvs, strings.Join(env, "\n"))
	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return 0, fmt.Errorf(clientMakeReqErrFmt, "Start", err)
	}
	if err := c.setRequestAuthHeader(req); err != nil {
		return 0, fmt.Errorf(clientLoginErrFmt, "Start", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.client.Do(req)
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
	requestURL := c.makeURL(endpointKill, cid)
	d := url.Values{}
	d.Set(fieldSignum, strconv.FormatInt(int64(signum), 10))

	req, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader(d.Encode()))
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "Kill", err)
	}

	if err := c.tlsHandShake(); err != nil {
		return err
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		return fmt.Errorf(clientLoginErrFmt, "Kill", err)
	}

	resp, err := c.client.Do(req)
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
	d := url.Values{}
	d.Set(fieldTimeout, strconv.FormatUint(timeout, 10))
	requestURL := c.makeURL(endpointRestart, cid, d.Encode())

	req, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		return fmt.Errorf(clientMakeReqErrFmt, "Restart", err)
	}

	if err := c.tlsHandShake(); err != nil {
		return err
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		return fmt.Errorf(clientLoginErrFmt, "Restart", err)
	}

	resp, err := c.client.Do(req)
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
	d := url.Values{}
	d.Set(fieldTimeout, strconv.FormatUint(timeout, 10))
	d.Set(fieldCapSize, strconv.FormatUint(capture_size, 10))
	requestURL := c.makeURL(endpointExec, cid, d.Encode())

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	if datafile != "" {
		if err := multipartFile(w, fieldStdin, datafile); err != nil {
			return nil, nil, fmt.Errorf("Invoke, prepare multipart error: %s", err)
		}
	}
	w.WriteField(fieldCommand, strings.Join(invocation, "\n"))
	w.WriteField(fieldEnvs, strings.Join(env, "\n"))
	w.Close()

	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return nil, nil, fmt.Errorf(clientMakeReqErrFmt, "Invoke", err)
	}

	if err := c.tlsHandShake(); err != nil {
		return nil, nil, err
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		return nil, nil, fmt.Errorf(clientLoginErrFmt, "Invoke", err)
	}
	req.Header.Add("Content-Type", w.FormDataContentType())

	resp, err := c.client.Do(req)
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
	requestURL := c.makeURL(endpointInspect, cid)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(clientMakeReqErrFmt, "Inspect", err)
	}
	if err := c.tlsHandShake(); err != nil {
		return nil, err
	}
	if err := c.setRequestAuthHeader(req); err != nil {
		return nil, fmt.Errorf(clientLoginErrFmt, "Inspect", err)
	}

	resp, err := c.client.Do(req)
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
	d := url.Values{}
	d.Set(fieldNonceLow, strconv.FormatUint(nonceLo, 10))
	d.Set(fieldNonceHigh, strconv.FormatUint(nonceHi, 10))
	d.Set(fieldReqType, strconv.FormatUint(uint64(reqType), 10))
	requestURL := c.makeURL(endpointReport, d.Encode())

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		e = fmt.Errorf(clientMakeReqErrFmt, "Report", err)
		return
	}

	if err := c.tlsHandShake(); err != nil {
		e = err
		return
	}

	if err := c.setRequestAuthHeader(req); err != nil {
		e = fmt.Errorf(clientLoginErrFmt, "Report", err)
		return
	}

	resp, err := c.client.Do(req)
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
	if err = json.Unmarshal(content, &r); err != nil {
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
