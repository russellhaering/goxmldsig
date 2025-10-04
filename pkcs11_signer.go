package dsig

import (
	"crypto"
	"crypto/x509"
	"errors"
	"io"
)

// PKCS11Signer is a generic implementation of the Signer interface using PKCS#11
// This is a template that can be used with various PKCS#11 libraries
type PKCS11Signer struct {
	// The actual signer implementation that performs the PKCS#11 operations
	// This should implement crypto.Signer
	pkcs11Signer crypto.Signer

	// The certificate associated with the private key
	certificate []byte

	// The hash algorithm to use
	hash crypto.Hash

	// The signature algorithm to use
	sigAlgorithm SignatureAlgorithm
}

// NewPKCS11Signer creates a new PKCS11 signer
func NewPKCS11Signer(signer crypto.Signer, cert []byte, hash crypto.Hash) (*PKCS11Signer, error) {
	if signer == nil {
		return nil, errors.New("signer cannot be nil")
	}

	if cert == nil || len(cert) == 0 {
		return nil, errors.New("certificate cannot be nil or empty")
	}

	// Determine the signature algorithm based on the signer type and hash
	var sigAlgorithm SignatureAlgorithm
	switch hash {
	case crypto.SHA1:
		sigAlgorithm = SignatureAlgorithm(RSASHA1SignatureMethod)
	case crypto.SHA256:
		sigAlgorithm = SignatureAlgorithm(RSASHA256SignatureMethod)
	case crypto.SHA384:
		sigAlgorithm = SignatureAlgorithm(RSASHA384SignatureMethod)
	case crypto.SHA512:
		sigAlgorithm = SignatureAlgorithm(RSASHA512SignatureMethod)
	default:
		// Default to SHA256
		sigAlgorithm = SignatureAlgorithm(RSASHA256SignatureMethod)
	}

	return &PKCS11Signer{
		pkcs11Signer: signer,
		certificate:  cert,
		hash:         hash,
		sigAlgorithm: sigAlgorithm,
	}, nil
}

// Sign implements the Signer interface for PKCS11
func (p *PKCS11Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// Use the PKCS11 signer to sign the digest
	return p.pkcs11Signer.Sign(nil, digest, p.hash)
}

// Algorithm returns the signature algorithm identifier
func (p *PKCS11Signer) Algorithm() SignatureAlgorithm {
	return p.sigAlgorithm
}

// GetCertificate implements the Signer interface
func (p *PKCS11Signer) GetCertificate() ([]byte, error) {
	return p.certificate, nil
}

// NewPKCS11SignerFromX509 creates a new PKCS11Signer from an X509 certificate
func NewPKCS11SignerFromX509(signer crypto.Signer, cert *x509.Certificate, hash crypto.Hash) (*PKCS11Signer, error) {
	if cert == nil {
		return nil, errors.New("certificate cannot be nil")
	}

	return NewPKCS11Signer(signer, cert.Raw, hash)
}
