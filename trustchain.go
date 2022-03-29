package globalsign

import (
	"net/http"
)

// TrustChainResponse GlobalSign API response of `/trustchain` endpoint.
type TrustChainResponse struct {
	Trustchain         []string `json:"trustchain"`
	OcspRevocationInfo []string `json:"ocsp_revocation_info"`
}

// TrustChain GlobalSign DSS trustchain API service.
func (s *globalSignDSSService) TrustChain() (*TrustChainResponse, error) {
	path := baseAPI + "/trustchain"
	result := new(TrustChainResponse)

	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
