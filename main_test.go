package dsig

import (
	"crypto"
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

func TestManifestExample(t *testing.T) {

	// Generate a key and self-signed certificate for signing
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	test := []byte{0x45, 0xf1, 0xab, 0xd7, 0x8a, 0x6f, 0x92, 0xe6, 0xa4, 0xb6, 0x8e, 0xba, 0x8f, 0xe7, 0x91, 0x96, 0xe0, 0xb2, 0x16, 0xd6, 0x0b, 0x82, 0x1b, 0x00, 0x45, 0xfa, 0xb8, 0xad, 0xd4, 0xfa, 0xff, 0xf9}

	sig := ctx.CreateSignature("id1234")
	err := ctx.AddManifestRef(sig, "package", crypto.SHA256, test)
	require.NoError(t, err)

	// Sign the signature
	signed, err := ctx.SignManifest(sig)
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
	manifest, err := vctx.ValidateManifest(signed)

	require.NoError(t, err)
	require.NotEmpty(t, manifest)
}

func TestMissingManifest(t *testing.T) {

	// Generate a key and self-signed certificate for signing
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	sig := ctx.CreateSignature("id1234")
	
	// Sign the signature
	_, err := ctx.SignManifest(sig)
	require.Error(t, err)
}

func TestRecursiveSigning(t *testing.T) {

	// Generate a key and self-signed certificate for signing
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	test := []byte{0x45, 0xf1, 0xab, 0xd7, 0x8a, 0x6f, 0x92, 0xe6, 0xa4, 0xb6, 0x8e, 0xba, 0x8f, 0xe7, 0x91, 0x96, 0xe0, 0xb2, 0x16, 0xd6, 0x0b, 0x82, 0x1b, 0x00, 0x45, 0xfa, 0xb8, 0xad, 0xd4, 0xfa, 0xff, 0xf9}

	sig := ctx.CreateSignature("id1234")
	err := ctx.AddManifestRef(sig, "package", crypto.SHA256, test)
	require.NoError(t, err)

	// Sign the signature
	signed, err := ctx.SignManifest(sig)
	require.NoError(t, err)

	list := &etree.Element{Tag: "Signatures"}
	list.AddChild(signed)

	// create second layer
	signed, err = ctx.SignEnveloped(list)
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
	manifest, err := vctx.ValidateManifest(signed)

	require.NoError(t, err)
	require.NotEmpty(t, manifest)
	require.Equal(t, len(manifest.References), 1)

	hash, digest, err := vctx.DecodeRef(&manifest.References[0])

	require.NoError(t, err)
	require.Equal(t, digest, test)
	require.Equal(t, hash, crypto.SHA256)
}
