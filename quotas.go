package globalsign

import (
	"net/http"
)

// QuotasResponse GlobalSign API response of `/quotas/signatures` and `/quotas/timestamps` endpoint.
type QuotasResponse struct {
	Value int `json:"value"`
}

// QuotasSignatures GlobalSign DSS quotas/signatures API service.
func (s *globalSignDSSService) QuotasSignatures() (*QuotasResponse, error) {
	path := baseAPI + "/quotas/signatures"
	result := new(QuotasResponse)

	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// QuotasTimestamps GlobalSign DSS quotas/timestamps API service.
func (s *globalSignDSSService) QuotasTimestamps() (*QuotasResponse, error) {
	path := baseAPI + "/quotas/timestamps"
	result := new(QuotasResponse)

	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
