package dsig

import (
	"crypto/x509"
	"testing"

	"github.com/beevik/etree"
)

// SignEnveloped must return a tree whose Signature is attached properly, so that
// validating the returned tree directly works, as it does after serialize+parse.
func TestSignEnvelopedValidatesInMemory(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<a ID="x"><b>t</b></a>`); err != nil {
		t.Fatal(err)
	}
	ks := RandomKeyStoreForTest()
	_, der, _ := ks.GetKeyPair()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewDefaultSigningContext(ks).SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	sig := signed.ChildElements()[1]
	if sig.Parent() != signed || sig.Index() != 1 {
		t.Fatalf("Signature parent set: %v, index %d, want true, 1", sig.Parent() == signed, sig.Index())
	}
	vc := NewDefaultValidationContext(&MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	if _, err := vc.Validate(signed); err != nil {
		t.Fatalf("in-memory Validate: %v", err)
	}
}
