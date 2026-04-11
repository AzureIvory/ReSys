package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestParsePartRef_WithRequireAndCmp(t *testing.T) {
	diskNumber, partNumber, err := ParsePartRef("12:34")
	require.NoError(t, err)

	got := struct {
		Disk int
		Part int
	}{
		Disk: diskNumber,
		Part: partNumber,
	}
	want := struct {
		Disk int
		Part int
	}{
		Disk: 12,
		Part: 34,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ParsePartRef mismatch (-want +got):\n%s", diff)
	}
}
