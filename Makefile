GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: sgx-host-verification-service installer docker all test clean

sgx-host-verification-service:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/scs/version.BuildDate=$(BUILDDATE) -X intel/isecl/sgx-host-verification-service/version.Version=$(VERSION) -X intel/isecl/sgx-host-verification-service/version.GitHash=$(GITCOMMIT)" -o out/sgx-host-verification-service

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html


installer: sgx-host-verification-service
	mkdir -p out/installer
	cp dist/linux/sgx-host-verification-service.service out/installer/sgx-host-verification-service.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/sgx-host-verification-service out/installer/sgx-host-verification-service
	makeself out/installer out/sgx-host-verification-service-$(VERSION).bin "SGX Host Verification Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgshvsdb.sh out/install_pgshvsdb.sh && chmod +x out/install_pgshvsdb.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/sgx-host-verification-service:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/sgx-host-verification-service:latest > ./out/docker-sgx-host-verification-service-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-sgx-host-verification-service
	cp dist/docker/docker-compose.yml out/docker-sgx-host-verification-service/docker-compose
	cp dist/docker/entrypoint.sh out/docker-sgx-host-verification-service/entrypoint.sh && chmod +x out/docker-sgx-host-verification-service/entrypoint.sh
	cp dist/docker/README.md out/docker-sgx-host-verification-service/README.md
	cp out/sgx-host-verification-service-$(VERSION).bin out/docker-sgx-host-verification-service/sgx-host-verification-service-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-sgx-host-verification-service/Dockerfile
	zip -r out/docker-sgx-host-verification-service.zip out/docker-sgx-host-verification-service	

all: test docker

clean:
	rm -f cover.*
	rm -f sgx-host-verification-service
	rm -rf out/
