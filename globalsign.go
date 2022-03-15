package globalsign

import (
	"errors"
	"time"
)

const (
	defaultBaseURL = "https://emea.api.dss.globalsign.com:8443"
	baseAPI        = "/v2"
	contentType    = "application/json;charset=utf-8"

	// Default authentication token time to live.
	authTokenTTL = 30 * time.Minute

	// Default identity time to live.
	identityTTL = 10 * time.Minute
)

// Errors definition.
var (
	ErrDigestRequired = errors.New("File digest required.")
)

type globalSignDSSService struct {
	client *Client
}
