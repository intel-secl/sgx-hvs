GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

.PHONY: docker shvs installer test clean

all: clean installer

shvs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/shvs/v3/version.BuildDate=$(BUILDDATE) -X intel/isecl/shvs/v3/version.Version=$(VERSION) -X intel/isecl/shvs/v3/version.GitHash=$(GITCOMMIT)" -o out/shvs

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.26.1/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.24/swagger-codegen-cli-3.0.24.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc:
	mkdir -p out/swagger
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

installer: shvs
	mkdir -p out/installer
	cp dist/linux/shvs.service out/installer/shvs.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/shvs out/installer/shvs
	makeself out/installer out/shvs-$(VERSION).bin "SGX Host Verification Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgshvsdb.sh out/install_pgshvsdb.sh && chmod +x out/install_pgshvsdb.sh

docker: installer
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} -f dist/image/Dockerfile -t isecl/shvs:$(VERSION) .
else
	docker build -f dist/image/Dockerfile -t isecl/shvs:$(VERSION) .
endif

shvs-oci-archive: docker
	skopeo copy docker-daemon:isecl/shvs:$(VERSION) oci-archive:out/shvs-$(VERSION)-$(GITCOMMIT).tar

clean:
	rm -f cover.*
	rm -rf out/
