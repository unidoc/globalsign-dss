package globalsign

// SigningRequest GlobalSign API request parameters of `/identity/{id}/sign/{digest}` endpoint.
type SigningRequest struct {
	ID string `json:"id"`

	// a hex encoded sha256 checksum for source file
	Digest string `json:"digest"`
}

// SigningResponse GlobalSign API response of `/identity/{id}/sign/{digest}` endpoint.
type SigningResponse struct {
	Signature string `json:"signature"`
}
