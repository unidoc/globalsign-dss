package globalsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

// DSSService availables GlobalSign Digital Signing Service.
type DSSService interface {
	Login(*LoginRequest) (*LoginResponse, error)
	Identity(*IdentityRequest) (*IdentityResponse, error)
	Timestamp(*TimestampRequest) (*TimestampResponse, error)
	Sign(*SigningRequest) (*SigningResponse, error)
	CertificatePath() (*CertificatePathResponse, error)
	TrustChain() (*TrustChainResponse, error)

	// DSS Identity and sign process services.
	DSSGetIdentity(context.Context, string, *IdentityRequest) (*DSSIdentity, error)
	DSSIdentitySign(context.Context, string, *IdentityRequest, []byte) ([]byte, error)
	DSSIdentityTimestamp(context.Context, string, *IdentityRequest, []byte) ([]byte, error)
}

// DSSIdentity represent acquired credential
// from login and identity request.
type DSSIdentity struct {
	ID          string
	SigningCert string
	OCSP        string
	CA          string
	Ts          time.Time
}

// DSSGetIdentity get identity information, signing certificate, OCSP, and CA certificat -
// automatically request identity if token expired.
func (s *globalSignDSSService) DSSGetIdentity(ctx context.Context, signer string, req *IdentityRequest) (*DSSIdentity, error) {
	// Check identity in vault.
	identity, ok := s.client.vault.Get(signer)
	if ok {
		return identity, nil
	}

	// Otherwise request new identity,
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	// Request id and signing certificate.
	identityResp, err := s.client.DSSService.Identity(req)
	if err != nil {
		return nil, err
	}

	// Request cs certificate.
	certResp, err := s.client.DSSService.CertificatePath()
	if err != nil {
		return nil, err
	}

	identity = &DSSIdentity{
		ID:          identityResp.ID,
		SigningCert: identityResp.SigningCert,
		OCSP:        identityResp.OCSPResponse,
		CA:          certResp.CA,
	}
	s.client.vault.Set(signer, identity)

	return identity, nil
}

// DSSIdentitySign request signature with signer and identity,
// automatically request identity if token expired.
func (s *globalSignDSSService) DSSIdentitySign(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := s.DSSGetIdentity(ctx, signer, identityReq)
	if err != nil {
		return nil, err
	}

	// Encode digest to hex.
	digestHex := strings.ToUpper(hex.EncodeToString(digest))
	signatureResp, err := s.client.DSSService.Sign(&SigningRequest{
		ID:     identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(signatureResp.Signature)
}

// DSSIdentityTimestamp add timestamp token to signer, automatically request identity if token expired.
func (s *globalSignDSSService) DSSIdentityTimestamp(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	err := s.client.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	// Encode digest to hex.
	digestHex := strings.ToUpper(hex.EncodeToString(digest))
	timestampResp, err := s.client.DSSService.Timestamp(&TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(timestampResp.Token)
}
