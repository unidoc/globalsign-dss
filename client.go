package globalsign

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Client implements a client for Globalsign Atlas DSS API service.
type Client struct {
	sync.RWMutex
	// httpClient used to communicate with the API.
	httpClient *http.Client

	// BaseURL base URL of API.
	BaseURL *url.URL

	// userAgent user agent for client header request.
	userAgent string

	// authToken token for authorization.
	authToken *string

	// authTokenTs authentication token timestamp.
	authTokenTs time.Time

	// DSSService Digital Signing Service (DSS).
	DSSService DSSService

	// vault store identity information.
	vault *IdentityVault

	// options globalsign client options.
	options *ClientOptions
}

// ClientOptions options for the globalsign client.
type ClientOptions struct {
	// BaseURL base url of API.
	BaseURL *url.URL

	// APIKey API key credentials.
	APIKey string

	// APISecret API secret credentials.
	APISecret string

	// CertFilePath path file to mTLS cert file.
	CertFilePath string

	// KeyFilePath path file to mTLS cert private key.
	KeyFilePath string
}

// NewClient initiates client with API Key, API Secret, Certificate file path, Private Key file path
// and returns the globalsign client.
func NewClient(apiKey, apiSecret, certPath, keyPath string) (*Client, error) {
	baseURL, err := url.Parse(defaultBaseURL)
	if err != nil {
		return nil, err
	}

	opts := &ClientOptions{
		BaseURL:      baseURL,
		APIKey:       apiKey,
		APISecret:    apiSecret,
		CertFilePath: certPath,
		KeyFilePath:  keyPath,
	}
	return NewClientWithOpts(opts)
}

// NewClientWithOpts initiates client with `ClientOptions` and returns the globasign client.
func NewClientWithOpts(opts *ClientOptions) (*Client, error) {
	// Create a http.Client with TLS.
	httpClient, err := newHTTPClientWithCertificate(opts.CertFilePath, opts.KeyFilePath)
	if err != nil {
		return nil, err
	}

	c := &Client{
		BaseURL:    opts.BaseURL,
		httpClient: httpClient,
		vault:      NewIdentityVault(identityTTL),
		options:    opts,
	}
	c.DSSService = &globalSignDSSService{client: c}

	return c, nil
}

// newHTTPClientWithCertificate initiate HTTP client with TLS.
func newHTTPClientWithCertificate(certPath, keyPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{cert},
	}
	tr := &http.Transport{TLSClientConfig: config}

	return &http.Client{Transport: tr}, nil
}

// DoNewRequest create new http client request and process the request.
func (c *Client) DoNewRequest(method, path string, result interface{}, params interface{}) error {
	// Generate request.
	req, err := c.NewRequest(method, path, params)
	if err != nil {
		return err
	}

	// Perform the request.
	err = c.Do(req, result)
	if err != nil {
		return err
	}

	// Return no errors on success.
	return nil
}

// NewRequest create new http client request.
func (c *Client) NewRequest(method string, path string, params interface{}) (*http.Request, error) {
	// Get base url.
	baseURL := *c.BaseURL

	// Add necessary address parts into the base url.
	reqURL := fmt.Sprintf("%s%s", baseURL.String(), path)

	var (
		req *http.Request
		err error
	)

	// Prepare request depending on it's type.
	if method == http.MethodGet {
		req, err = http.NewRequest(method, reqURL, nil)
		if err != nil {
			return nil, err
		}
		// Prepare necessary parameters.
		urlParams, ok := params.(map[string]string)
		if ok {
			values := url.Values{}
			for k, v := range urlParams {
				values.Set(k, v)
			}
			req.URL.RawQuery = values.Encode()
		}
	} else {
		var buf io.ReadWriter
		if params != nil {
			buf = new(bytes.Buffer)
			err := json.NewEncoder(buf).Encode(params)
			if err != nil {
				return nil, err
			}
		}

		req, err = http.NewRequest(method, reqURL, buf)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// Do process the http request.
func (c *Client) Do(req *http.Request, result interface{}) error {
	// Authenticate request.
	if c.authToken != nil {
		req.Header.Add("Authorization", "Bearer "+*c.authToken)
	}

	if c.userAgent != "" {
		req.Header.Add("User-Agent", c.userAgent)
	}

	// Perform request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response for error.
	if err := checkResponse(resp); err != nil {
		return err
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

// SetAuthToken sets authentication token of the client.
func (c *Client) SetAuthToken(at string) {
	c.authToken = &at
}

// SetUserAgent sets user agent of the client.
func (c *Client) SetUserAgent(ua string) {
	c.userAgent = ua
}

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf(string(data))
}

// Response wraps standard http Response with default response fields
// which returned from api.
type Response struct {
	*http.Response
}

// ensureToken automatically request new token if token expired.
func (c *Client) ensureToken(ctx context.Context) error {
	c.RLock()
	token := ""
	if c.authToken != nil {
		token = *c.authToken
	}

	tokenTs := c.authTokenTs
	c.RUnlock()

	// If token not yet acquired or expired.
	if token == "" || time.Since(tokenTs) > authTokenTTL {
		resp, err := c.DSSService.Login(&LoginRequest{
			APIKey:    c.options.APIKey,
			APISecret: c.options.APISecret,
		})
		if err != nil {
			return err
		}

		c.Lock()
		c.authToken = &resp.AccessToken
		c.authTokenTs = time.Now()
		c.Unlock()
	}

	return nil
}
