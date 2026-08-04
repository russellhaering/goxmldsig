package etreeutils

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// nestedElement builds the tree directly rather than parsing it, so that the
// depth under test stays independent of etree's ReadSettings.MaxDepth.
func nestedElement(t *testing.T, depth int) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	root := doc.CreateElement("root")
	root.CreateAttr("xmlns", "http://example.org")

	el := root
	for i := 0; i < depth; i++ {
		el = el.CreateElement("a")
	}

	return root
}

func TestNSDetatchLimit(t *testing.T) {
	detached, err := NSDetatch(NewDefaultNSContext(), nestedElement(t, 10))
	require.NoError(t, err)
	require.NotNil(t, detached)

	_, err = NSDetatch(NewDefaultNSContext(), nestedElement(t, 5000))
	require.ErrorIs(t, err, ErrTraversalLimit)
}
