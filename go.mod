module intel/isecl/cms

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.0
	github.com/sirupsen/logrus v1.3.0
	github.com/stretchr/testify v1.2.2
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v0.0.0-20190318062745-1f49aa09d2f5
