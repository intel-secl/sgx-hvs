module intel/isecl/shvs/v4

require (

	github.com/google/uuid v1.1.2
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.10
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.0
	github.com/stretchr/testify v1.3.0
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/common/v4 v4.0.2
)

replace intel/isecl/lib/common/v4 => github.com/intel-secl/common/v4 v4.0.2
