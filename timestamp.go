package globalsign

// TimestampRequest GlobalSign API request parameters of `/timestamp/{digest}` endpoint.
type TimestampRequest struct {
	Digest string `json:"digest"`
}

// TimestampResponse GlobalSign API response of `/timestamp/{digest}` endpoint.
type TimestampResponse struct {
	Token string `json:"token"`
}
