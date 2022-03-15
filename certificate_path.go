package globalsign

import (
	"net/http"
)

// CertificatePathResponse GlobalSign API response of `/certificate_path` endpoint.
type CertificatePathResponse struct {
	CA string `json:"path"`
}

// CertificatePath GlobalSign DSS certificate_path API service.
func (s *globalSignDSSService) CertificatePath() (*CertificatePathResponse, error) {
	path := baseAPI + "/certificate_path"

	result := new(CertificatePathResponse)
	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
