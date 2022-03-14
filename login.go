package globalsign

// LoginRequest GlobalSign API request parameters of `/login` endpoint.
type LoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// LoginResponse GlobalSign API response of `/login` endpoint.
type LoginResponse struct {
	AccessToken string `json:"access_token"`
}
