package tasks

import (
	"intel/isecl/lib/common/setup"
	"intel/isecl/cms/config"
	"os"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("CMS_PORT", "1337")
	os.Setenv("CMS_KEY_ALGORITHM", "RSA")
	os.Setenv("CMS_KEY_LENGTH", "3072")

	c := config.Configuration{}
	s := Server{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Run(ctx)
	assert.Equal(t, 1337, c.Port)
	assert.Equal(t, "RSA", c.KeyAlgorithm)
	
}

