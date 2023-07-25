package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"
)

type X509KeyStore interface {
	GetKeyPair() (privateKey crypto.Signer, cert []byte, err error)
}

type X509ChainStore interface {
	GetChain() (certs [][]byte, err error)
}

type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

type MemoryX509KeyStore struct {
	privateKey crypto.Signer
	cert       []byte
}

func (ks *MemoryX509KeyStore) GetKeyPair() (crypto.Signer, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}
