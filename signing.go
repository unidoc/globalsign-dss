package globalsign

import (
	"net/http"
)

// SigningRequest GlobalSign API request parameters of `/identity/{id}/sign/{digest}` endpoint.
type SigningRequest struct {
	ID string `json:"id"`

	// Digest is the hex encoded SHA256 checksum of a source file.
	Digest string `json:"digest"`
}

// SigningResponse GlobalSign API response of `/identity/{id}/sign/{digest}` endpoint.
type SigningResponse struct {
	Signature string `json:"signature"`
}

// Sign GlobalSign DSS sign API service.
func (s *globalSignDSSService) Sign(req *SigningRequest) (*SigningResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/identity/" + req.ID + "/sign/" + req.Digest

	result := new(SigningResponse)
	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
