module intel/isecl/shvs/v3

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.16
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/clients/v3 v3.4.0
	intel/isecl/lib/common/v3 v3.4.0
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.4.0
replace intel/isecl/lib/clients/v3 => github.com/intel-secl/clients/v3 v3.4.0
