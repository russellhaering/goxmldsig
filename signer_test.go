package dsig

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefaultSigningContextWithSigner(t *testing.T) {
	// Create a random key store for testing
	ks := RandomKeyStoreForTest()
	key, cert, err := ks.GetKeyPair()
	require.NoError(t, err)

	// Create a FileSigner
	signer, err := NewFileSigner(key, cert, crypto.SHA256)
	require.NoError(t, err)

	// Create a signing context with the signer
	ctx := NewDefaultSigningContextWithSigner(signer)
	require.NotNil(t, ctx)
	require.Equal(t, crypto.SHA256, ctx.Hash)
	require.Equal(t, DefaultIdAttr, ctx.IdAttribute)
	require.Equal(t, DefaultPrefix, ctx.Prefix)

	// Verify the algorithm is correct
	method := ctx.GetSignatureMethodIdentifier()
	require.Equal(t, RSASHA256SignatureMethod, method)
}

func TestSignerFileSigner(t *testing.T) {
	// Create a random key store for testing
	ks := RandomKeyStoreForTest()
	key, cert, err := ks.GetKeyPair()
	require.NoError(t, err)

	// Create a FileSigner
	signer, err := NewFileSigner(key, cert, crypto.SHA256)
	require.NoError(t, err)

	// Verify the algorithm matches what we expect
	require.Equal(t, SignatureAlgorithm(RSASHA256SignatureMethod), signer.Algorithm())

	// Verify the certificate is returned correctly
	certBytes, err := signer.GetCertificate()
	require.NoError(t, err)
	require.Equal(t, cert, certBytes)

	// Create a proper hash of data before signing
	hash := crypto.SHA256.New()
	hash.Write([]byte("test message"))
	digest := hash.Sum(nil)

	// Sign the proper digest
	sig, err := signer.Sign(nil, digest, crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
}
