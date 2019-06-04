package constants

const (
	CMS_HOME_DIR           = "/opt/cms"
	CMS_CONFIG_DIR         = "/etc/cms"
	CMS_LOG_DIR            = "/var/log/cms"
	CMS_DATA_DIR           = "/var/lib/cms"
	CMS_RUNTIME_INFO_DIR   = "/var/run/cms"
	CMS_ROOT_CA_CERT       = "/var/lib/cms/rootCA.crt"
	CMS_ROOT_CA_KEY        = "/var/lib/cms/rootCA.key"
	CMS_TLS_CERT           = "/var/lib/cms/Tls.crt"
	CMS_TLS_KEY            = "/var/lib/cms/Tls.key"
	CMS_HTTP_LOG           = "/var/log/cms/http.log"
	CMS_PID_FILE           = "/var/run/cms/cms.pid"
	CMS_BIN_SOFTLINK       = "/usr/local/bin/cms"
	CMS_CONFIG_FILE        = "/etc/cms/config.yml"
	CMS_SERIAL_NUMBER_FILE = "/var/lib/cms/serial-number"

	// CMS_NOSETUP is a boolean environment variable for skipping WLS Setup tasks
	CMS_NOSETUP = "CMS_NOSETUP"

	// CMS_PORT is an integer environment variable for specifying the port WLS should listen on
	CMS_PORT = "CMS_PORT"

	// CMS_USERNAME is a string environment variable for specifying the username to use for the database connection
	CMS_USERNAME = "CMS_USERNAME"

	// CMS_PASSWORD is a string environment variable for specifying the password to use for the database connection
	CMS_PASSWORD = "CMS_PASSWORD"

	CMS_CA_CERT_VALIDITY = "CMS_CA_CERT_VALIDITY"

	CMS_ORGANIZATION = "CMS_ORGANIZATION"

	CMS_LOCALITY = "CMS_LOCALITY"

	CMS_PROVINCE = "CMS_PROVINCE"

	CMS_COUNTRY = "CMS_COUNTRY"

	CMS_CA_CERT_SAN_LIST = "CMS_CA_CERT_SAN_LIST"

	CMS_WHITELISTED_CN_LIST = "CMS_WHITELISTED_CN_LIST"

	CMS_CA_CERT_SIGNING_EXTENSIONS = "CMS_CA_CERT_SIGNING_EXTENSIONS"

	CMS_LOGLEVEL = "CMS_LOGLEVEL"
)
