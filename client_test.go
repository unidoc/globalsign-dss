package globalsign

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/timestamp"
	"golang.org/x/crypto/ocsp"
)

var (
	apiKey     = os.Getenv("GLOBALSIGN_DSS_API_KEY")
	apiSecret  = os.Getenv("GLOBALSIGN_DSS_API_SECRET")
	apiBaseURL = "https://emea.api.dss.globalsign.com:8443"
	certPath   = os.Getenv("GLOBALSIGN_DSS_CERT_PATH")
	keyPath    = os.Getenv("GLOBALSIGN_DSS_KEY_PATH")
)

func TestSign(t *testing.T) {
	t.Log("---Run TestSign---")
	t.Logf("Login with API Key: %s and Secret: %s\n", apiKey, apiSecret)
	t.Logf("Cert path: %s and Private Key path: %s", certPath, keyPath)

	baseURL, err := url.Parse(apiBaseURL)
	if err != nil {
		t.Fatalf("Error parse API base URL: %v", err.Error())
	}

	co := &ClientOptions{
		BaseURL:      baseURL,
		APIKey:       apiKey,
		APISecret:    apiSecret,
		CertFilePath: certPath,
		KeyFilePath:  keyPath,
	}

	c, err := NewClientWithOpts(co)
	if err != nil {
		t.Fatalf("Error on initializing client: %v\n", err)
	}

	resp, err := c.DSSService.Login(&LoginRequest{APIKey: apiKey, APISecret: apiSecret})
	if err != nil {
		t.Fatalf("Login failed: %v", err.Error())
	}

	t.Logf("Access Token: %s\n", resp.AccessToken)
	c.SetAuthToken(resp.AccessToken)

	// get identity
	identity, err := c.DSSService.Identity(&IdentityRequest{
		SubjectDn: SubjectDn{},
	})
	if err != nil {
		t.Fatalf("Identity failed: %v", err.Error())
	}

	t.Logf("ID: %s\n", identity.ID)
	t.Logf("Signing Cert: %s\n", identity.SigningCert)
	t.Logf("OCSP Response: %s\n", identity.OCSPResponse)

	// get certificate path
	cert, err := c.DSSService.CertificatePath()
	if err != nil {
		t.Fatalf("CerticatePath failed: %s\n", err.Error())
	}
	t.Logf("CA Certificate: %s\n", cert.CA)

	// Create certificate chain from signing and CA cert.
	var certChain []*x509.Certificate
	issuerCertData := []byte(identity.SigningCert)
	for len(issuerCertData) != 0 {
		var block *pem.Block
		block, issuerCertData = pem.Decode(issuerCertData)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("x509.Certificate parse failed: %s\n", err.Error())
		}

		certChain = append(certChain, issuer)
	}

	caCertData := []byte(cert.CA)
	for len(caCertData) != 0 {
		var block *pem.Block
		block, caCertData = pem.Decode(caCertData)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("x509.Certificate parse failed: %s\n", err.Error())
		}

		certChain = append(certChain, issuer)
	}

	ocspDecoded, err := base64.StdEncoding.DecodeString(identity.OCSPResponse)
	if err != nil {
		t.Fatalf("OCSP decode failed: %s\n", err.Error())
	}

	ocspResponse, err := ocsp.ParseResponse(ocspDecoded, certChain[1])
	if err != nil {
		t.Fatalf("OCSP Error: %s\n", err.Error())
	}
	t.Logf("OCSP: %v\n", ocspResponse)

	// Mock digest.
	digest := sha256.Sum256([]byte(fmt.Sprintf("%x", time.Now().Unix())))

	// Encode to hex.
	digestHex := strings.ToUpper(hex.EncodeToString(digest[:]))

	t.Logf("Digest: %s\n", digestHex)

	// Get timestamp.
	timestampResp, err := c.DSSService.Timestamp(&TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		t.Fatalf("Timestamp failed: %s\n", err.Error())
	}

	t.Logf("Timestamp: %s\n", timestampResp.Token)

	decodedTs, err := base64.StdEncoding.DecodeString(timestampResp.Token)
	if err != nil {
		t.Fatalf("Error while decode timestamp token: %s\n", err.Error())
	}

	t.Logf("Timestamp: %s\n", string(decodedTs))

	tsResp, err := timestamp.Parse(decodedTs)
	if err != nil {
		t.Fatalf("Timestamp parse failed: %v\n", err.Error())
	}

	t.Logf("Timestamp Token: %v\n", tsResp)

	// Get signature.
	signature, err := c.DSSService.Sign(&SigningRequest{
		ID:     identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		t.Error(err)
		t.Fatalf("Sign failed: %s\n", err.Error())
	}

	t.Logf("Signature: %s\n", signature.Signature)

	signatureHash, err := hex.DecodeString(signature.Signature)
	if err != nil {
		t.Fatalf("Hex decode failed: %s\n", err.Error())
	}

	t.Logf("Signature: %s", string(signatureHash))

	trustChain, err := c.DSSService.TrustChain()
	if err != nil {
		t.Fatalf("TrusChain failed: %s\n", err.Error())
	}

	t.Logf("Trust Chain trustchain: %v\n", trustChain.Trustchain)
	t.Logf("Trust Chain ocsp_revocation_info: %v\n", trustChain.OcspRevocationInfo)

	validationPolicy, err := c.DSSService.ValidationPolicy()
	if err != nil {
		t.Fatalf("ValidationPolicy failed: %s\n", err.Error())
	}

	t.Logf("Validation Policy: %v\n", validationPolicy)

	quotasSignatures, err := c.DSSService.QuotasSignatures()
	if err != nil {
		t.Fatalf("QuotasSignatures failed: %s\n", err.Error())
	}

	t.Logf("Quotas Signatures: %v\n", quotasSignatures.Value)

	quotasTimestamps, err := c.DSSService.QuotasTimestamps()
	if err != nil {
		t.Fatalf("QuotasTimestamps failed: %s\n", err.Error())
	}

	t.Logf("Quotas Timestamps: %v\n", quotasTimestamps.Value)
}
