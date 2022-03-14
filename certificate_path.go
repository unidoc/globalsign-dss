package globalsign

// CertificatePathResponse GlobalSign API response of `/certificate_path` endpoint.
type CertificatePathResponse struct {
	CA string `json:"path"`
}
