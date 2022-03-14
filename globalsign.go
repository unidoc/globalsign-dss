package globalsign

import (
	"errors"
	"net/http"
	"time"
)

const (
	defaultBaseURL = "https://emea.api.dss.globalsign.com:8443"
	baseAPI        = "/v2"
	contentType    = "application/json;charset=utf-8"

	// Default authentication token time to live.
	authTokenTTL = 30 * time.Minute

	// Default identity time to live.
	identityTTL = 10 * time.Minute
)

// Errors definition.
var (
	ErrDigestRequired = errors.New("file digest required")
)

type globalSignDSSService struct {
	client *Client
}

// Login GlobalSign DSS login API service.
func (s *globalSignDSSService) Login(req *LoginRequest) (*LoginResponse, error) {
	if req == nil {
		req = &LoginRequest{}
	}

	path := baseAPI + "/login"
	r, err := s.client.NewRequest(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	result := new(LoginResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Identity GlobalSign DSS identity API service.
func (s *globalSignDSSService) Identity(req *IdentityRequest) (*IdentityResponse, error) {
	path := baseAPI + "/identity"
	r, err := s.client.NewRequest(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	result := new(IdentityResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Timestamp GlobalSign DSS timestamp API service.
func (s *globalSignDSSService) Timestamp(req *TimestampRequest) (*TimestampResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/timestamp/" + req.Digest
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(TimestampResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Sign GlobalSign DSS sign API service.
func (s *globalSignDSSService) Sign(req *SigningRequest) (*SigningResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/identity/" + req.ID + "/sign/" + req.Digest
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(SigningResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CertificatePath GlobalSign DSS certificate_path API service.
func (s *globalSignDSSService) CertificatePath() (*CertificatePathResponse, error) {
	path := baseAPI + "/certificate_path"
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(CertificatePathResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// TrusChain GlobalSign DSS trustchain API service.
func (s *globalSignDSSService) TrustChain() (*TrustChainResponse, error) {
	path := baseAPI + "/certificate_path"
	r, err := s.client.NewRequest(http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, err
	}

	result := new(TrustChainResponse)
	err = s.client.Do(r, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
