package globalsign

import (
	"net/http"
)

// ValidationPolicyResponse GlobalSign API response of `/validationpolicy` endpoint.
type ValidationPolicyResponse struct {
	SubjectDn ValidationPolicySubjectDn `json:"subject_dn"`
}

// ValidationPolicySubjectDn GlobalSign API response of `/validationpolicy` endpoint `subject_dn`.
type ValidationPolicySubjectDn struct {
	CommonName                                     PresenceFormat         `json:"common_name"`
	Organization                                   PresenceFormat         `json:"organization"`
	OrganizationUnit                               OrganizationUnit       `json:"organization_unit"`
	Country                                        PresenceFormat         `json:"country"`
	State                                          PresenceFormat         `json:"state"`
	Locality                                       PresenceFormat         `json:"locality"`
	StreetAddress                                  PresenceFormat         `json:"street_address"`
	Email                                          PresenceFormat         `json:"email"`
	JurisdictionOfIncorporationLocalityName        PresenceFormat         `json:"jurisdiction_of_incorporation_locality_name"`
	JurisdictionOfIncorporationStateOrProvinceName PresenceFormat         `json:"jurisdiction_of_incorporation_state_or_province_name"`
	JurisdictionOfIncorporationCountryName         PresenceFormat         `json:"jurisdiction_of_incorporation_country_name"`
	ExtraAttributes                                map[string]interface{} `json:"extra_attributes"`
}

// PresenceFormat `presence` and `format` GlobalSign API response of `/validationpolicy` endpoint.
type PresenceFormat struct {
	Presence string `json:"presence"`
	Format   string `json:"format"`
}

// OrganizationUnit `organizational_unit` GlobalSign API response of `/validationpolicy` endpoint.
type OrganizationUnit struct {
	Static   bool     `json:"static"`
	List     []string `json:"list"`
	MinCount int      `json:"min_count"`
	MaxCount int      `json:"max_count"`
}

// ValidationPolicy GlobalSign DSS validationpolicyAPI service.
func (s *globalSignDSSService) ValidationPolicy() (*ValidationPolicyResponse, error) {
	path := baseAPI + "/validationpolicy"
	result := new(ValidationPolicyResponse)

	err := s.client.DoNewRequest(http.MethodGet, path, result, struct{}{})
	if err != nil {
		return nil, err
	}

	return result, nil
}
