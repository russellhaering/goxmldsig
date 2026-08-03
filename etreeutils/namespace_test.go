package etreeutils

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func nestedElement(t *testing.T, depth int) *etree.Element {
	t.Helper()

	var b strings.Builder
	b.WriteString(`<root xmlns="http://example.org">`)
	for i := 0; i < depth; i++ {
		b.WriteString("<a>")
	}
	for i := 0; i < depth; i++ {
		b.WriteString("</a>")
	}
	b.WriteString(`</root>`)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(b.String()))
	return doc.Root()
}

func TestNSDetatchLimit(t *testing.T) {
	detached, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, 10))
	require.NoError(t, err)
	require.NotNil(t, detached)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, 5000))
	require.ErrorIs(t, err, ErrTraversalLimit)
}
