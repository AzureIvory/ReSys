package utils

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestScriptSmoke(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
	})
}
