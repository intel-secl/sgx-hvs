module intel/isecl/shvs/v3

require (

	github.com/google/uuid v1.1.2
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.10
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/common/v3 v3.5.0
)

replace intel/isecl/lib/common/v3 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.5/develop
