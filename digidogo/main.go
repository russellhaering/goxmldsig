package main

import (
	"os"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	// Generate a key and self-signed certificate for signing
	randomKeyStore := dsig.RandomKeyStoreForTest()
	ctx := dsig.NewDefaultSigningContext(randomKeyStore)

	// Sign the element
	signedElement, err := ctx.SignEnvelopedReader(os.Args[1])
	if err != nil {
		panic(err)
	}

	// Serialize the signed element. It is important not to modify the element
	// after it has been signed - even pretty-printing the XML will invalidate
	// the signature.
	doc := etree.NewDocument()
	doc.SetRoot(signedElement)
	str, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}

	println(str)
}
