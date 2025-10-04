package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
)

// SignatureAlgorithm represents the algorithm used to sign the digest
type SignatureAlgorithm string

// Signer represents an entity capable of creating digital signatures
type Signer interface {
	// Sign creates a signature for the given digest
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)

	// Algorithm returns the signature algorithm identifier for this signer
	Algorithm() SignatureAlgorithm

	// GetCertificate returns the certificate associated with this signer
	GetCertificate() ([]byte, error)
}

// FileSigner implements the Signer interface using a local RSA private key
type FileSigner struct {
	privateKey *rsa.PrivateKey
	cert       []byte
	hash       crypto.Hash
}

// NewFileSigner creates a new signer from a private key and certificate
func NewFileSigner(privateKey *rsa.PrivateKey, cert []byte, hash crypto.Hash) (*FileSigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	return &FileSigner{
		privateKey: privateKey,
		cert:       cert,
		hash:       hash,
	}, nil
}

// Sign implements the Signer interface for file-based keys
func (fs *FileSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, fs.privateKey, fs.hash, digest)
}

// Algorithm returns the signature algorithm identifier
func (fs *FileSigner) Algorithm() SignatureAlgorithm {
	switch fs.hash {
	case crypto.SHA1:
		return SignatureAlgorithm(RSASHA1SignatureMethod)
	case crypto.SHA256:
		return SignatureAlgorithm(RSASHA256SignatureMethod)
	case crypto.SHA384:
		return SignatureAlgorithm(RSASHA384SignatureMethod)
	case crypto.SHA512:
		return SignatureAlgorithm(RSASHA512SignatureMethod)
	default:
		// Default to SHA256
		return SignatureAlgorithm(RSASHA256SignatureMethod)
	}
}

// GetCertificate implements the Signer interface
func (fs *FileSigner) GetCertificate() ([]byte, error) {
	return fs.cert, nil
}
