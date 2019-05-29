module intel/isecl/cms

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.0
	github.com/sirupsen/logrus v1.3.0
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common v0.0.0-20190313181840-64ac706d9590
