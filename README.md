SGX HVS
=======

`SGX-Host Verification Service (SHVS)` is responsible for registering
SGX Agent and collecting SGX Data from the host.

Key features
------------

-   SHVS communicates with SCS to determine if the platform is up to
    date on hardware and security patches (TCB)
-   SHVS saves platform specific information in its own database which
    will be pulled by SGX integration hub
-   SGX-HVS extracts platform specific values from SGX Agent and pushes
    them to SGX caching service

System Requirements
-------------------

-   RHEL 8.2
-   Epel 8 Repo
-   Proxy settings if applicable

Software requirements
---------------------

-   git
-   makeself
-   Go 1.14.1 or newer

Step By Step Build Instructions
===============================

Install required shell commands
-------------------------------

### Install tools from `dnf`

``` {.shell}
sudo dnf install -y git wget makeself
```

### Install `go 1.14.1` or newer

The `Host Verification Service` requires Go version 1.14 that has
support for `go modules`. The build was validated with version 1.14.1
version of `go`. It is recommended that you use a newer version of `go`
- but please keep in mind that the product has been validated with
1.14.1 and newer versions of `go` may introduce compatibility issues.
You can use the following to install `go`.

``` {.shell}
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
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
make all
```

### Manage service

-   Start service
    -   shvs start
-   Stop service
    -   shvs stop
-   Restart service
    -   shvs restart
-   Status of service
    -   shvs status

Third Party Dependencies
========================

Certificate Management Service
------------------------------

Authentication and Authorization Service
----------------------------------------

### Direct dependencies

  Name       Repo URL                            Minimum Version Required
  ---------- ----------------------------- ------------------------------------
  uuid       github.com/google/uuid                       v1.1.1
  errors     github.com/pkg/errors                        V0.9.1
  handlers   github.com/gorilla/handlers                  v1.4.0
  mux        github.com/gorilla/mux                       v1.7.3
  jwt-go     github.com/dgrijalva/jwt-go           v3.2.0+incompatible
  gorm       github.com/jinzhu/gorm                      v1.9.10
  logrus     github.com/sirupsen/logrus                   v1.4.0
  testify    github.com/stretchr/testify                  v1.3.0
  crypto     golang.org/x/crypto            v0.0.0-20190325154230-a5d413f7728c
  time       golang.org/x/time              v0.0.0-20190308202827-9d24e82272b4
  yaml.v2    gopkg.in/yaml.v2                             v2.2.2
  client     intel/isecl/lib/clients                      v3.0.0
  common     intel/isecl/lib/common                    v3.0/develop

### Indirect Dependencies

  Repo URL                     Minimum version required
  --------------------------- --------------------------
  https://github.com/lib/pq             1.0.0

*Note: All dependencies are listed in go.mod*

Links
=====

<https://01.org/intel-secl/>
