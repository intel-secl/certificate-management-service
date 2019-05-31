package config

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	csetup "intel/isecl/lib/common/setup"
	"os"
	"strconv"
)

// Do not use this casing for GoLang constants unless you are making it match environment variable syntax in bash

// CMS_NOSETUP is a boolean environment variable for skipping WLS Setup tasks
const CMS_NOSETUP = "CMS_NOSETUP"

// CMS_PORT is an integer environment variable for specifying the port WLS should listen on
const CMS_PORT = "CMS_PORT"

// CMS_USERNAME is a string environment variable for specifying the username to use for the database connection
const CMS_USERNAME = "CMS_USERNAME"

// CMS_PASSWORD is a string environment variable for specifying the password to use for the database connection
const CMS_PASSWORD = "CMS_PASSWORD"

const CMS_CA_CERT_VALIDITY = "CMS_CA_CERT_VALIDITY"

const CMS_ORGANIZATION = "CMS_ORGANIZATION"

const CMS_LOCALITY = "CMS_ORGANIZATION"

const CMS_PROVINCE = "CMS_PROVINCE"

const CMS_COUNTRY = "CMS_COUNTRY"

const CMS_CA_CERT_SAN_LIST = "CMS_CA_CERT_SAN_LIST"

const CMS_CA_CERT_SIGNING_EXTENSIONS = "CMS_CA_CERT_SIGNING_EXTENSIONS"

const CMS_LOGLEVEL = "CMS_LOGLEVEL"

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
var Configuration struct {
	Port           string
	CACertValidity int
	Organization   string
	Locality       string
	Province       string
	Country        string
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
			CMS_PORT,
			&Configuration.Port,
			"CMS Port",
			true,
		},
		{
                        "CMS_CA_CERT_VALIDITY",
                        &Configuration.CACertValidity,
                        "CMS Certificate Validity",
                        true,
                },
		{
                        "CMS_ORGANIZATION",
                        &Configuration.Organization,
                        "CMS Organization",
                        true,
                },
		{
                        "CMS_LOCALITY",
                        &Configuration.Locality,
                        "CMS Locality",
                        true,
                },
		{
                        "CMS_PROVINCE",
                        &Configuration.Province,
                        "CMS Province",
                        true,
                },
		{
                        "CMS_COUNTRY",
                        &Configuration.Country,
                        "CMS Country",
                        true,
                },
	}

	for _, cv := range requiredConfigs {
		_, _, err = c.OverrideValueFromEnvVar(cv.Name, cv.ConfigVar, cv.Description, cv.EmptyOkay)
		fmt.Println(cv.Name + ": " + strconv.FormatBool(cv.EmptyOkay))
		if err != nil {
			fmt.Println(err)
			requiredConfigsPresent = false
			log.Errorf("environment variable %s required - but not set", cv.Name)
		}
	}
	if requiredConfigsPresent {
		Configuration.ConfigComplete = true
		return Save()
	}
	return fmt.Errorf("one or more required environment variables for setup not present. log file has details")
}

func LoadConfiguration() {
	// load from config
	file, err := os.Open("/etc/cms/config.yml")
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&Configuration)
	}
}
