package main

import (
	"archive/zip"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path"
	"regexp"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	inputName := os.Args[1]

	// Generate a key and self-signed certificate for signing
	randomKeyStore := dsig.RandomKeyStoreForTest()
	ctx := dsig.NewDefaultSigningContext(randomKeyStore)

	// Sign the element
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	signedElement, err := ctx.SignEnvelopedReader(inputName, input)
	if err != nil {
		panic(err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(signedElement)

	edoc, err := os.Create(
		string(regexp.MustCompile("\\.[^\\.]+$").ReplaceAll(
			[]byte(inputName), []byte(".edoc"),
		)),
	)
	if err != nil {
		panic(err)
	}
	w := zip.NewWriter(edoc)

	{
		f, err := w.Create("META-INF/manifest.xml")
		if err != nil {
			panic(err)
		}

		root := etree.NewDocument()
		manifest := root.CreateElement("manifest")
		manifest.Space = "manifest"

		entry := manifest.CreateElement("file-entry")
		entry.Space = "manifest"
		entry.Attr = append(entry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "full-path",
			Value: "/",
		})
		entry.Attr = append(entry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "media-type",
			Value: "application/vnd.etsi.asic-e+zip",
		})

		fileEntry := manifest.CreateElement("file-entry")
		fileEntry.Space = "manifest"
		fileEntry.Attr = append(fileEntry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "full-path",
			Value: path.Base(inputName),
		})
		fileEntry.Attr = append(fileEntry.Attr, etree.Attr{
			Space: "manifest",
			Key:   "media-type",
			Value: mime.TypeByExtension(inputName),
		})

		output, err := root.WriteToString()
		println(output)
		if err != nil {
			panic(err)
		}
		f.Write([]byte(output))
	}

	edocSigns, err := w.Create("META-INF/edoc-signatures-S1.xml")
	if err != nil {
		panic(err)
	}
	str, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}
	println(str)
	edocSigns.Write([]byte(str))

	f, err := w.Create(path.Base(inputName))
	if err != nil {
		panic(err)
	}
	f.Write(input)

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	if err := edoc.Close(); err != nil {
		log.Fatal(err)
	}
}
