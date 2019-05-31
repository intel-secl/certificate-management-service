package setup

import (
	"fmt"
	"intel/isecl/cms/config"
	csetup "intel/isecl/lib/common/setup"

	log "github.com/sirupsen/logrus"
)

type Configurer struct {
}

func (cnfr Configurer) Run(c csetup.Context) error {
	// save configuration from config.yml
	if cnfr.Validate(c) == nil {
		log.Debug("Configuration is complete")
		return nil
	}

	err := config.SaveConfiguration(c)
	if err != nil {
		return err
	}

	return nil
}

func (cnfr Configurer) Validate(c csetup.Context) error {

	if config.Configuration.ConfigComplete != true {
		return fmt.Errorf("Configuration is not complete")
	}
	return nil
}
