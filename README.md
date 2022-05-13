SGX HVS
=======

SGX Host Verification Service aggregates the platform enablement info from multiple SGX Agent instances.

Key features
------------

-   SHVS saves platform specific information provided by a sgx agent instance, in its own database which will be pulled by integration hub later

System Requirements
-------------------

-   RHEL 8.2
-   Epel 8 Repo
-   Proxy settings if applicable

Software requirements
---------------------

-   git
-   makeself
-   docker
-   Go 1.14.4

Step By Step Build Instructions
===============================

Install required shell commands
-------------------------------

### Install tools from `dnf`

``` {.shell}
sudo dnf install -y git wget makeself docker
```

### Install `go 1.14.4`

The `Host Verification Service` requires Go version 1.14 that has
support for `go modules`. The build was validated with version 1.14.4
version of `go`. It is recommended that you use a newer version of `go`
- but please keep in mind that the product has been validated with
1.14.4 and newer versions of `go` may introduce compatibility issues.
You can use the following to install `go`.

``` {.shell}
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
tar -xzf go1.14.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

Build SGX-Host Verification Service
-----------------------------------

-   Git clone the SGX Host Verification Service
-   Run scripts to build the SGX Host Verification Service

``` {.shell}
git clone https://github.com/intel-secl/sgx-hvs.git
cd sgx-hvs
git checkout v4.0.3
make all
```

### Manage service

-   Start service
    -   shvs start
-   Stop service
    -   shvs stop
-   Status of service
    -   shvs status

Third Party Dependencies
========================

Certificate Management Service
------------------------------

Authentication and Authorization Service
----------------------------------------

### Direct dependencies

|  Name       | Repo URL                      | Minimum Version Required  |
|  ---------- | ----------------------------- | :-----------------------: |
|  uuid       | github.com/google/uuid        | v1.1.2                    |
|  errors     | github.com/pkg/errors         | V0.9.1                    |
|  handlers   | github.com/gorilla/handlers   | v1.4.0                    |
|  mux        | github.com/gorilla/mux        | v1.7.3                    |
|  gorm       | github.com/jinzhu/gorm        | v1.9.10                   |
|  logrus     | github.com/sirupsen/logrus    | v1.4.0                    |
|  testify    | github.com/stretchr/testify   | v1.3.0                    |
|  yaml.v2    | gopkg.in/yaml.v2              | v2.4.0                    |
|  common     | github.com/intel-secl/common  | v4.0.3                    |

### Indirect Dependencies

  Repo URL                     Minimum version required
  --------------------------- --------------------------
  https://github.com/lib/pq             1.1.0

*Note: All dependencies are listed in go.mod*
