package globalsign

import (
	"net/http"
)

// TimestampRequest GlobalSign API request parameters of `/timestamp/{digest}` endpoint.
type TimestampRequest struct {
	Digest string `json:"digest"`
}

// TimestampResponse GlobalSign API response of `/timestamp/{digest}` endpoint.
type TimestampResponse struct {
	Token string `json:"token"`
}

// Timestamp GlobalSign DSS timestamp API service.
func (s *globalSignDSSService) Timestamp(req *TimestampRequest) (*TimestampResponse, error) {
	if req == nil {
		return nil, ErrDigestRequired
	}

	path := baseAPI + "/timestamp/" + req.Digest
	result := new(TimestampResponse)
	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
