package config

import (
	"fmt"
	"intel/isecl/cms/constants"
	csetup "intel/isecl/lib/common/setup"
	"os"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
var Configuration struct {
	Port           string
	CACertValidity int
	Organization   string
	Locality       string
	Province       string
	Country        string
	WhitelistedCN  string
	ConfigComplete bool
}

// Save the configuration struct into /etc/cms/config.ynml
func Save() error {
	file, err := os.OpenFile("/etc/cms/config.yml", os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create("/etc/cms/config.yml")
			if err != nil {
				return err
			}
		} else {
			// some other I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(Configuration)
}

// SaveConfiguration is used to save configurations that are provided in environment during setup tasks
// This is called when setup tasks are called
func SaveConfiguration(c csetup.Context) error {
	var err error

	//clear the ConfigComplete flag and save the file. We will mark it complete on at the end.
	// we can use the ConfigComplete field to check if the configuration is complete before
	// running the other tasks.
	Configuration.ConfigComplete = false
	err = Save()
	if err != nil {
		return fmt.Errorf("unable to save configuration file")
	}

	// we are going to check and set the required configuration variables
	// however, we do not want to error out after each one. We want to provide
	// entries in the log file indicating which ones are missing. At the
	// end of this section we will error out. Will use a flag to keep track

	requiredConfigsPresent := true

	requiredConfigs := [...]csetup.EnvVars{

		{
			constants.CMS_PORT,
			&Configuration.Port,
			"CMS Port",
			true,
		},
		{
			constants.CMS_CA_CERT_VALIDITY,
			&Configuration.CACertValidity,
			"CMS Certificate Validity",
			true,
		},
		{
			constants.CMS_ORGANIZATION,
			&Configuration.Organization,
			"CMS Organization",
			true,
		},
		{
			constants.CMS_LOCALITY,
			&Configuration.Locality,
			"CMS Locality",
			true,
		},
		{
			constants.CMS_PROVINCE,
			&Configuration.Province,
			"CMS Province",
			true,
		},
		{
			constants.CMS_COUNTRY,
			&Configuration.Country,
			"CMS Country",
			true,
		},
		{
			constants.CMS_WHITELISTED_CN_LIST,
			&Configuration.WhitelistedCN,
			"Common Names of Whitelisted Services",
			false,
		},
	}

	for _, cv := range requiredConfigs {
		_, _, err = c.OverrideValueFromEnvVar(cv.Name, cv.ConfigVar, cv.Description, cv.EmptyOkay)
		if err != nil {
			fmt.Println(err)
			requiredConfigsPresent = false
			log.Errorf("Environment variable %s required - but not set", cv.Name)
		}
	}
	if requiredConfigsPresent {
		Configuration.ConfigComplete = true
		return Save()
	}
	return fmt.Errorf("One or more required environment variables for setup not present. log file has details")
}

//LoadConfiguration loads the CMS configuration from config.yml file
func LoadConfiguration() {
	// load from config
	file, err := os.Open(constants.CMS_CONFIG_FILE)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&Configuration)
	}
}
