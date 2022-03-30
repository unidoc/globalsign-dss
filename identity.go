package globalsign

import (
	"net/http"
)

// IdentityRequest GlobalSign API request parameters of `/identity` endpoint.
type IdentityRequest struct {
	SubjectDn SubjectDn `json:"subject_dn"`
}

// SubjectDn parameter of `subject_dn`.
type SubjectDn struct {
	Country                                        string                    `json:"country,omitempty"`
	State                                          string                    `json:"state,omitempty"`
	Locality                                       string                    `json:"locality,omitempty"`
	StreetAddress                                  string                    `json:"street_address,omitempty"`
	Organization                                   string                    `json:"organization,omitempty"`
	OrganizationUnit                               []string                  `json:"organization_unit,omitempty"`
	CommonName                                     string                    `json:"common_name,omitempty"`
	Email                                          string                    `json:"email,omitempty"`
	JurisdictionOfIncorporationLocalityName        string                    `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
	JurisdictionOfIncorporationStateOrProvinceName string                    `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
	JurisdictionOfIncorporationCountryName         string                    `json:"jurisdiction_of_incorporation_country_name,omitempty"`
	BusinessCategory                               string                    `json:"business_category,omitempty"`
	ExtraAttributes                                []SubjectDnExtraAttribute `json:"extra_attributes,omitempty"`
}

// SubjectDnExtraAttribute extra attributes for parameter `extra_attributes`.
type SubjectDnExtraAttribute struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// IdentityResponse GlobalSign API response of `/identity` endpoint.
type IdentityResponse struct {
	ID           string `json:"id"`
	SigningCert  string `json:"signing_cert"`
	OCSPResponse string `json:"ocsp_response"`
}

// Identity GlobalSign DSS identity API service.
func (s *globalSignDSSService) Identity(req *IdentityRequest) (*IdentityResponse, error) {
	path := baseAPI + "/identity"

	result := new(IdentityResponse)
	err := s.client.DoNewRequest(http.MethodPost, path, result, req)
	if err != nil {
		return nil, err
	}

	return result, nil
}
