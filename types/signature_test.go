package types

import (
	"testing"

	"github.com/austdev/goxmldsig/etreeutils"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestMapPathAndRemove(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(`<X><Y/><Y><RemoveMe xmlns="x"/></Y></X>`)
	require.NoError(t, err)

	el, err := etreeutils.NSFindOne(doc.Root(), "x", "RemoveMe")
	require.NoError(t, err)
	require.NotNil(t, el)

	path := mapPathToElement(doc.Root(), el)
	removed := removeElementAtPath(doc.Root(), path)
	require.True(t, removed)

	el, err = etreeutils.NSFindOne(doc.Root(), "x", "RemoveMe")
	require.NoError(t, err)
	require.Nil(t, el)
}
