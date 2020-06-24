GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: shvs installer docker all test clean

shvs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/shvs/version.BuildDate=$(BUILDDATE) -X intel/isecl/shvs/version.Version=$(VERSION) -X intel/isecl/shvs/version.GitHash=$(GITCOMMIT)" -o out/shvs

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
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/shvs:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/shvs:latest > ./out/docker-shvs-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-shvs
	cp dist/docker/docker-compose.yml out/docker-shvs/docker-compose
	cp dist/docker/entrypoint.sh out/docker-shvs/entrypoint.sh && chmod +x out/docker-shvs/entrypoint.sh
	cp dist/docker/README.md out/docker-shvs/README.md
	cp out/shvs-$(VERSION).bin out/docker-shvs/shvs-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-shvs/Dockerfile
	zip -r out/docker-shvs.zip out/docker-shvs

all: test docker

clean:
	rm -f cover.*
	rm -f shvs
	rm -rf out/
