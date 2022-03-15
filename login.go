package globalsign

import (
	"net/http"
)

// LoginRequest GlobalSign API request parameters of `/login` endpoint.
type LoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// LoginResponse GlobalSign API response of `/login` endpoint.
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

// Login GlobalSign DSS login API service.
func (s *globalSignDSSService) Login(req *LoginRequest) (*LoginResponse, error) {
	if req == nil {
		req = &LoginRequest{}
	}

	path := baseAPI + "/login"
	result := new(LoginResponse)
	err := s.client.DoNewRequest(http.MethodPost, path, result, req)
	if err != nil {
		return nil, err
	}

	return result, nil
}
