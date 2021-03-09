package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

type SigningContext struct {
	Hash          crypto.Hash
	KeyStore      X509KeyStore
	IdAttribute   string
	Prefix        string
	Canonicalizer Canonicalizer
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   DefaultIdAttr,
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}
}

func (ctx *SigningContext) SetSignatureMethod(algorithmID string) error {
	hash, ok := signatureMethodsByIdentifier[algorithmID]
	if !ok {
		return fmt.Errorf("Unknown SignatureMethod: %s", algorithmID)
	}

	ctx.Hash = hash

	return nil
}

func (ctx *SigningContext) digest(el *etree.Element) ([]byte, error) {
	if ctx.GetDigestAlgorithmIdentifier() == "" {
		return nil, errors.New("unsupported hash mechanism")
	}

	canonical, err := ctx.Canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}
	return ctx.hash(canonical)
}

func (ctx *SigningContext) hash(data []byte) ([]byte, error) {
	hash := ctx.Hash.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *SigningContext) constructSignedInfo(digest []byte, uri string, enveloped bool, transform bool) (*etree.Element, error) {
	digestAlgorithmIdentifier := ctx.GetDigestAlgorithmIdentifier()
	signatureMethodIdentifier := ctx.GetSignatureMethodIdentifier()
	if signatureMethodIdentifier == "" {
		return nil, errors.New("unsupported signature method")
	}

	signedInfo := &etree.Element{
		Tag:   SignedInfoTag,
		Space: ctx.Prefix,
		Attr: []etree.Attr{
			{Key: "Id", Value: "S1-SignedInfo"},
		},
	}

	// /SignedInfo/CanonicalizationMethod
	canonicalizationMethod := ctx.createNamespacedElement(signedInfo, CanonicalizationMethodTag)
	canonicalizationMethod.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/SignatureMethod
	signatureMethod := ctx.createNamespacedElement(signedInfo, SignatureMethodTag)
	signatureMethod.CreateAttr(AlgorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)
	reference.CreateAttr("Id", "S1-ref-1")
	reference.CreateAttr(URIAttr, uri)

	// /SignedInfo/Reference/Transforms
	if transform {
		transforms := ctx.createNamespacedElement(reference, TransformsTag)
		if enveloped {
			envelopedTransform := ctx.createNamespacedElement(transforms, TransformTag)
			envelopedTransform.CreateAttr(AlgorithmAttr, EnvelopedSignatureAltorithmId.String())
		}
		canonicalizationAlgorithm := ctx.createNamespacedElement(transforms, TransformTag)
		canonicalizationAlgorithm.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))
	}

	// /SignedInfo/Reference/DigestMethod
	digestMethod := ctx.createNamespacedElement(reference, DigestMethodTag)
	digestMethod.CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

	// /SignedInfo/Reference/DigestValue
	digestValue := ctx.createNamespacedElement(reference, DigestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return signedInfo, nil
}

func (ctx *SigningContext) ConstructSignature(el *etree.Element, enveloped bool) (*etree.Element, error) {
	digest, err := ctx.digest(el)
	if err != nil {
		return nil, err
	}

	dataId := el.SelectAttrValue(ctx.IdAttribute, "")
	uri := ""
	if dataId != "" {
		uri = "#" + dataId
	}

	signedInfo, err := ctx.constructSignedInfo(digest, uri, enveloped, true)
	if err != nil {
		return nil, err
	}

	sig := ctx.baseSig(signedInfo)

	// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
	// of the SignedInfo must declare all namespaces that are in scope at it's final
	// enveloped location in the document. In order to do that, we're going to construct
	// a series of cascading NSContexts to capture namespace declarations:

	// First get the context surrounding the element we are signing.
	rootNSCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}

	// Then capture any declarations on the element itself.
	elNSCtx, err := rootNSCtx.SubContext(el)
	if err != nil {
		return nil, err
	}

	// Followed by declarations on the Signature (which we just added above)
	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	// Finally detatch the SignedInfo in order to capture all of the namespace
	// declarations in the scope we've constructed.
	detatchedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}

	return ctx.constructSig(detatchedSignedInfo, sig)
}

func (ctx *SigningContext) baseSig(signedInfo *etree.Element) *etree.Element {
	return &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
		Attr: []etree.Attr{
			{Space: "xmlns", Key: ctx.Prefix, Value: Namespace},
			{Key: "Id", Value: "S1"},
		},
		Child: []etree.Token{
			signedInfo,
		},
	}
}

func (ctx *SigningContext) constructSig(signedInfo *etree.Element, sig *etree.Element) (*etree.Element, error) {
	digest, err := ctx.digest(signedInfo)
	if err != nil {
		return nil, err
	}

	key, cert, err := ctx.KeyStore.GetKeyPair()
	if err != nil {
		return nil, err
	}

	certs := [][]byte{cert}
	if cs, ok := ctx.KeyStore.(X509ChainStore); ok {
		certs, err = cs.GetChain()
		if err != nil {
			return nil, err
		}
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest)
	if err != nil {
		return nil, err
	}

	signatureValue := ctx.createNamespacedElement(sig, SignatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := ctx.createNamespacedElement(sig, KeyInfoTag)
	x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)
	for _, cert := range certs {
		x509Certificate := ctx.createNamespacedElement(x509Data, X509CertificateTag)
		x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert))
	}

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
}

func (ctx *SigningContext) xadesSigningCertificate() (*etree.Element, error) {
	sigCert := &etree.Element{
		Space: "xades",
		Tag:   "SigningCertificate",
	}

	_, cert, err := ctx.KeyStore.GetKeyPair()
	if err != nil {
		return nil, err
	}

	h, err := ctx.hash(cert)
	if err != nil {
		return nil, err
	}
	sigCert.Child = append(sigCert.Child,
		&etree.Element{
			Space: "xades",
			Tag:   "Cert",
			Child: []etree.Token{
				&etree.Element{
					Space: "xades",
					Tag:   "CertDigest",
					Child: []etree.Token{
						&etree.Element{
							Space: "ds",
							Tag:   "DigestMethod",
							Attr: []etree.Attr{
								{Key: "Algorithm", Value: "http://www.w3.org/2001/04/xmlenc#sha256"},
							},
						},
						&etree.Element{
							Space: "ds",
							Tag:   "DigestValue",
							Child: []etree.Token{
								&etree.CharData{Data: base64.StdEncoding.EncodeToString(h)},
							},
						},
					},
				},
				&etree.Element{
					Space: "xades",
					Tag:   "IssuerSerial",
					Child: []etree.Token{
						&etree.Element{
							Space: "ds",
							Tag:   "X509IssuerName",
							Child: []etree.Token{
								&etree.CharData{Data: "CN=,O=,C="},
							},
						},
						&etree.Element{
							Space: "ds",
							Tag:   "X509IssuerSerialNumber",
							Child: []etree.Token{
								&etree.CharData{Data: "serialnumber"},
							},
						},
					},
				},
			},
		},
	)

	return sigCert, nil
}

func (ctx *SigningContext) xadesSignedSignatureProperties() (*etree.Element, error) {
	sigCert, err := ctx.xadesSigningCertificate()
	if err != nil {
		return nil, err
	}

	return &etree.Element{
		Space: "xades",
		Tag:   "SignedSignatureProperties",
		Attr: []etree.Attr{
			{Key: "Id", Value: "S1-SignedSignatureProperties"},
		},
		Child: []etree.Token{
			&etree.Element{
				Space: "xades",
				Tag:   "SigningTime",
				Child: []etree.Token{
					&etree.CharData{Data: time.Now().Format(time.RFC3339)},
				},
			},
			sigCert,
			&etree.Element{
				Space: "xades",
				Tag:   "SignatureProductionPlace",
			},
			&etree.Element{
				Space: "xades",
				Tag:   "SignerRole",
				Child: []etree.Token{
					&etree.Element{
						Space: "xades",
						Tag:   "ClaimedRoles",
						Child: []etree.Token{
							&etree.Element{
								Space: "xades",
								Tag:   "ClaimedRole",
							},
						},
					},
				},
			},
		},
	}, nil
}

func (ctx *SigningContext) xadesUnsignedSignatureProperties() (*etree.Element, error) {
	return &etree.Element{
		Space: "xades",
		Tag:   "UnsignedProperties",
		Attr: []etree.Attr{
			{Key: "Id", Value: "S1-UnsignedProperties"},
		},
		Child: []etree.Token{
			&etree.Element{
				Space: "xades",
				Tag:   "UnsignedSignatureProperties",
				Attr: []etree.Attr{
					{Key: "Id", Value: "S1-UnsignedSignatureProperties"},
				},
				Child: []etree.Token{
					&etree.Element{
						Space: "xades",
						Tag:   "SignatureTimeStamp",
						Attr: []etree.Attr{
							{Key: "Id", Value: "S1-ts-0"},
						},
						Child: []etree.Token{
							&etree.Element{
								Space: "ds",
								Tag:   "CanonicalizationMethod",
								Attr: []etree.Attr{
									{Key: "Algorithm", Value: "http://www.w3.org/2006/12/xml-c14n11"},
								},
								Child: []etree.Token{},
							},
							&etree.Element{
								Space: "xades",
								Tag:   "EncapsulatedTimeStamp",
								Attr:  []etree.Attr{},
								Child: []etree.Token{
									&etree.CharData{Data: "Some cool hash"},
								},
							},
						},
					},
					&etree.Element{
						Space: "xades",
						Tag:   "RevocationValues",
						Attr:  []etree.Attr{},
						Child: []etree.Token{
							&etree.Element{
								Space: "xades",
								Tag:   "OCSPValues",
								Attr:  []etree.Attr{},
								Child: []etree.Token{
									&etree.Element{
										Space: "xades",
										Tag:   "EncapsulatedOCSPValue",
										Attr:  []etree.Attr{},
										Child: []etree.Token{
											&etree.CharData{Data: "Some cool hash"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

func (ctx *SigningContext) SignXAdES(uri string, input []byte) (*etree.Element, error) {
	sig := etree.NewElement("XAdESSignatures")
	sig.Space = "asic"
	sig.Attr = append(sig.Attr, etree.Attr{
		Space: "xmlns",
		Key:   "asic",
		Value: "http://uri.etsi.org/02918/v1.2.1#",
	})

	dsig, err := ctx.SignEnvelopedReader(uri, input)
	if err != nil {
		return nil, err
	}

	sigProp, err := ctx.xadesSignedSignatureProperties()
	if err != nil {
		return nil, err
	}

	sigObjProp := &etree.Element{
		Space: "xades",
		Tag:   "SignedDataObjectProperties",
		Child: []etree.Token{
			&etree.Element{
				Space: "xades",
				Tag:   "DataObjectFormat",
				Attr: []etree.Attr{
					{Key: "ObjectReference", Value: "#S1-ref-1"},
				},
				Child: []etree.Token{
					&etree.Element{
						Space: "xades",
						Tag:   "MimeType",
						Child: []etree.Token{
							&etree.CharData{Data: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
						},
					},
				},
			},
		},
	}

	unsigProps, err := ctx.xadesUnsignedSignatureProperties()
	if err != nil {
		return nil, err
	}

	dsig.AddChild(&etree.Element{
		Space: "ds",
		Tag:   "Object",
		Child: []etree.Token{
			&etree.Element{
				Space: "xades",
				Tag:   "QualifyingProperties",
				Attr: []etree.Attr{
					{Space: "xmlns", Key: "xades", Value: "http://uri.etsi.org/01903/v1.3.2#"},
					{Key: "Id", Value: "S1-QualifyingProperties"},
					{Key: "Target", Value: "#S1"},
				},
				Child: []etree.Token{
					&etree.Element{
						Space: "xades",
						Tag:   "SignedProperties",
						Attr: []etree.Attr{
							{Key: "Id", Value: "S1-SignedProperties"},
						},
						Child: []etree.Token{
							sigProp, sigObjProp,
						},
					},
					unsigProps,
				},
			},
		},
	})
	sig.AddChild(dsig)

	return sig, nil
}

func (ctx *SigningContext) SignEnvelopedReader(uri string, input []byte) (*etree.Element, error) {
	digest, err := ctx.hash(input)
	if err != nil {
		return nil, err
	}

	signedInfo, err := ctx.constructSignedInfo(digest, uri, false, false)
	if err != nil {
		return nil, err
	}

	return ctx.constructSig(signedInfo, ctx.baseSig(signedInfo))
}

func (ctx *SigningContext) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

func (ctx *SigningContext) GetSignatureMethodIdentifier() string {
	if ident, ok := signatureMethodIdentifiers[ctx.Hash]; ok {
		return ident
	}
	return ""
}

func (ctx *SigningContext) GetDigestAlgorithmIdentifier() string {
	if ident, ok := digestAlgorithmIdentifiers[ctx.Hash]; ok {
		return ident
	}
	return ""
}

// Useful for signing query string (including DEFLATED AuthnRequest) when
// using HTTP-Redirect to make a signed request.
// See 3.4.4.1 DEFLATE Encoding of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
func (ctx *SigningContext) SignString(content string) ([]byte, error) {
	hash := ctx.Hash.New()
	if ln, err := hash.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("error calculating hash: %v", err)
	} else if ln < 1 {
		return nil, fmt.Errorf("zero length hash")
	}
	digest := hash.Sum(nil)

	var signature []byte
	if key, _, err := ctx.KeyStore.GetKeyPair(); err != nil {
		return nil, fmt.Errorf("unable to fetch key for signing: %v", err)
	} else if signature, err = rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest); err != nil {
		return nil, fmt.Errorf("error signing: %v", err)
	}
	return signature, nil
}
