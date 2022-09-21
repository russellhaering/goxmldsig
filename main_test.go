package dsig

import (
	"crypto/x509"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestDocumentedExample(t *testing.T) {

	// Generate a key and self-signed certificate for signing
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)
	elementToSign := &etree.Element{
		Tag: "ExampleElement",
	}
	elementToSign.CreateAttr("ID", "id1234")

	dataValue := elementToSign.CreateElement("XData")
	dataValue.CreateAttr("kind", "test")
	dataValue.SetText("zip: 586a6289e2ff09b0826dd1daeab5237735a3a728afc48d11976bbed1fbaeaf0a")

	// Sign the element
	signedElement, err := ctx.SignEnveloped(elementToSign)
	require.NoError(t, err)

	// Validate
	_, certData, err := ctx.KeyStore.GetKeyPair()
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certData)
	require.NoError(t, err)

	// Construct a signing context with one or more roots of trust.
	vctx := NewDefaultValidationContext(&MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})

	// It is important to only use the returned validated element.
	// See: https://www.w3.org/TR/xmldsig-bestpractices/#check-what-is-signed
	validated, err := vctx.Validate(signedElement)
	require.NoError(t, err)
	require.NotEmpty(t, validated)
}
