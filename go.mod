module intel/isecl/cms/v2

require (
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.15
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/common/v2 v2.2.1
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.2.1
