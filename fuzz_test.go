package dsig

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// seed corpus: a minimal signed XML document
var fuzzSeedXML = `<Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#resp1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></Response>`

func FuzzValidate(f *testing.F) {
	f.Add([]byte(fuzzSeedXML))
	f.Add([]byte(`<root ID="r1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>dGVzdA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></root>`))
	f.Add([]byte(`<a xmlns:ns1="http://example.com" xmlns:ns2="http://example.org"><ns1:b><ns2:c/></ns1:b></a>`))
	f.Add([]byte(`<x></x>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		certStore := &MemoryX509CertificateStore{
			Roots: []*x509.Certificate{},
		}

		ctx := NewDefaultValidationContext(certStore)
		ctx.Clock = NewFakeClockAt(time.Date(2016, 3, 15, 0, 22, 0, 0, time.UTC))

		// Errors are expected; we're looking for panics and hangs.
		ctx.Validate(root)
	})
}

func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(`<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val">text</a:child></root>`))
	f.Add([]byte(`<r xmlns="http://default"><child xmlns:x="http://x" x:a="1"/></r>`))
	f.Add([]byte(`<e xmlns:ns1="http://ns1" xmlns:ns2="http://ns2"><ns1:a><ns2:b ns1:c="d"><!-- comment --></ns2:b></ns1:a></e>`))
	f.Add([]byte(`<a xml:lang="en" xml:space="preserve">  text  </a>`))

	canonicalizers := []Canonicalizer{
		MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
		MakeC14N11Canonicalizer(),
		MakeC14N11WithCommentsCanonicalizer(),
		MakeC14N10RecCanonicalizer(),
		MakeC14N10WithCommentsCanonicalizer(),
		MakeNullCanonicalizer(),
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		for _, c := range canonicalizers {
			// Canonicalize a fresh copy for each canonicalizer,
			// since some transform in-place.
			c.Canonicalize(root.Copy())
		}
	})
}

func FuzzSignRoundTrip(f *testing.F) {
	f.Add([]byte(`<root ID="id123"><child>content</child></root>`))
	f.Add([]byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1"><saml:Issuer>test</saml:Issuer></saml:Assertion>`))
	f.Add([]byte(`<doc xmlns:a="http://a.example" xmlns:b="http://b.example"><a:el b:attr="v">data</a:el></doc>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		// Limit input size to keep signing tractable
		if len(data) > 1024*64 {
			return
		}

		ks := RandomKeyStoreForTest()
		sigCtx := NewDefaultSigningContext(ks)

		signed, err := sigCtx.SignEnveloped(root)
		if err != nil {
			return
		}

		// Validate what we just signed
		key, cert, err := ks.GetKeyPair()
		if err != nil {
			return
		}
		_ = key

		parsedCert, err := x509.ParseCertificate(cert)
		if err != nil {
			return
		}

		certStore := &MemoryX509CertificateStore{
			Roots: []*x509.Certificate{parsedCert},
		}

		valCtx := NewDefaultValidationContext(certStore)
		valCtx.Validate(signed)
	})
}

const oktaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a
-----END CERTIFICATE-----`

func FuzzValidateWithCert(f *testing.F) {
	f.Add([]byte(fuzzSeedXML))

	block, _ := pem.Decode([]byte(oktaCertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		f.Fatal(err)
	}

	certStore := &MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(data)
		if err != nil {
			return
		}

		root := doc.Root()
		if root == nil {
			return
		}

		ctx := NewDefaultValidationContext(certStore)
		ctx.Clock = NewFakeClockAt(time.Date(2016, 3, 15, 0, 22, 0, 0, time.UTC))

		// Errors are expected; we're looking for panics and hangs.
		ctx.Validate(root)
	})
}
