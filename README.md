# globalsign-dss
Client SDK for GlobalSign Digital Signing Service API.

# Requirements
- mTLS certificate
- Private Key that used to generate mTLS
- API credentials

# Usage
Example usage:
- For [unipdf](https://github.com/unidoc/unipdf "UniPDF") integration with unipdf see **unipdf-examples**.
```go
...

// Create GlobalSign client.
client, err := globalsign.NewClient("<API_KEY>", "<API_SECRET>", "<KEY_PATH>", "<CERT_PATH>")
if err != nil {
	return err
}

// Create signature handler.
handler, err := sign_handler.NewGlobalSignDSS(context.Background(), manager, option.SignedBy, map[string]interface{}{
	"common_name": "UniDoc"
})
if err != nil {
	return err
}
```

# License Information
This source code package is licensed with MIT license.  
However, when used in a software package with UniPDF it obeys the UniDoc EULA which is available at: https://unidoc.io/eula/

# Credits
Thanks to [@wja-id](https://github.com/wja-id).  
This package is modified from [https://github.com/wja-id/globalsign-sdk](https://github.com/wja-id/globalsign-sdk)