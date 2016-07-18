package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
)

type SigningContext struct {
	Hash        crypto.Hash
	KeyStore    X509KeyStore
	IdAttribute string
	Prefix      string
	Algorithm   SignatureAlgorithm
	IsOkta      bool
}

func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:        crypto.SHA256,
		KeyStore:    ks,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
		Algorithm:   CanonicalXML11AlgorithmId,
	}
}

func (ctx *SigningContext) digest(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(canonicalize(el, ctx.Algorithm, false))
	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	hash := ctx.Hash.New()
	_, err := doc.WriteTo(hash)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (ctx *SigningContext) constructSignedInfo(el *etree.Element, enveloped bool) (*etree.Element, error) {
	digestAlgorithmIdentifier, ok := digestAlgorithmIdentifiers[ctx.Hash]
	if !ok {
		return nil, errors.New("unsupported hash mechanism")
	}

	signatureMethodIdentifier, ok := signatureMethodIdentifiers[ctx.Hash]
	if !ok {
		return nil, errors.New("unsupported signature method")
	}

	digest, err := ctx.digest(el)
	if err != nil {
		return nil, err
	}

	signedInfo := &etree.Element{
		Tag:   SignedInfoTag,
		Space: ctx.Prefix,
	}

	// /SignedInfo/CanonicalizationMethod
	canonicalizationMethod := ctx.createNamespacedElement(signedInfo, CanonicalizationMethodTag)
	canonicalizationMethod.CreateAttr(AlgorithmAttr, string(ctx.Algorithm))

	// /SignedInfo/SignatureMethod
	signatureMethod := ctx.createNamespacedElement(signedInfo, SignatureMethodTag)
	signatureMethod.CreateAttr(AlgorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)

	dataId := el.SelectAttrValue(DefaultIdAttr, "")
	if dataId == "" {
		return nil, errors.New("Missing data ID")
	}

	reference.CreateAttr(URIAttr, "#"+dataId)

	// /SignedInfo/Reference/Transforms
	transforms := ctx.createNamespacedElement(reference, TransformsTag)
	if enveloped {
		envelopedTransform := ctx.createNamespacedElement(transforms, TransformTag)
		envelopedTransform.CreateAttr(AlgorithmAttr, EnvelopedSignatureAltorithmId)
	}
	canonicalizationAlgorithm := ctx.createNamespacedElement(transforms, TransformTag)
	canonicalizationAlgorithm.CreateAttr(AlgorithmAttr, string(ctx.Algorithm))

	// /SignedInfo/Reference/DigestMethod
	digestMethod := ctx.createNamespacedElement(reference, DigestMethodTag)
	digestMethod.CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

	// /SignedInfo/Reference/DigestValue
	digestValue := ctx.createNamespacedElement(reference, DigestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return signedInfo, nil
}

func (ctx *SigningContext) constructSignature(el *etree.Element, enveloped bool) (*etree.Element, error) {
	signedInfo, err := ctx.constructSignedInfo(el, enveloped)
	if err != nil {
		return nil, err
	}

	sig := &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
	}

	xmlns := "xmlns"
	if ctx.Prefix != "" {
		xmlns += ":" + ctx.Prefix
	}

	sig.CreateAttr(xmlns, Namespace)

	sig.Child = append(sig.Child, signedInfo)

	// Must propagate down the attributes to the 'SignedInfo' before digesting
	for _, attr := range sig.Attr {
		signedInfo.CreateAttr(attr.Space+":"+attr.Key, attr.Value)
	}

	digest, err := ctx.digest(signedInfo)
	if err != nil {
		return nil, err
	}

	key, cert, err := ctx.KeyStore.GetKeyPair()
	if err != nil {
		return nil, err
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest)
	if err != nil {
		return nil, err
	}

	signatureValue := ctx.createNamespacedElement(sig, SignatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := ctx.createNamespacedElement(sig, KeyInfoTag)
	x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)
	x509Certificate := ctx.createNamespacedElement(x509Data, X509CertificateTag)
	x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert))

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
}

func (ctx *SigningContext) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	sig, err := ctx.constructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}
