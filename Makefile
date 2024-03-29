GITCOMMIT := $(shell git describe --always)
VERSION := "v5.1.0"
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
MONOREPO_GITURL := "https://github.com/intel-innersource/applications.security.isecl.intel-secl.git"
MONOREPO_GITBRANCH := "v5.1/develop"

ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

.PHONY: docker shvs installer k8s test clean 

shvs:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/shvs/v5/version.BuildDate=$(BUILDDATE) -X intel/isecl/shvs/v5/version.Version=$(VERSION) -X intel/isecl/shvs/v5/version.GitHash=$(GITCOMMIT)" -o out/shvs

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.26.1/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.24/swagger-codegen-cli-3.0.24.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc:
	mkdir -p out/swagger
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy
	env GOOS=linux GOSUMDB=off GOPROXY=direct \
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

test:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go mod tidy
	env GOOS=linux GOSUMDB=off GOPROXY=direct go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

installer: shvs
	mkdir -p out/installer
	cp dist/linux/shvs.service out/installer/shvs.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/shvs out/installer/shvs

	git clone --depth 1 -b $(MONOREPO_GITBRANCH) $(MONOREPO_GITURL) tmp_monorepo
	cp -a tmp_monorepo/pkg/lib/common/upgrades/* out/installer/
	rm -rf tmp_monorepo
	cp -a upgrades/* out/installer
	mv out/installer/build/* out/installer
	chmod +x out/installer/*.sh

	makeself out/installer out/shvs-$(VERSION).bin "SGX Host Verification Service $(VERSION)" ./install.sh

docker: shvs
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} --label org.label-schema.build-date=$(BUILDDATE)  -f dist/image/Dockerfile -t $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)-$(GITCOMMIT) .
else
	docker build -f dist/image/Dockerfile --label org.label-schema.build-date=$(BUILDDATE) -t $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)-$(GITCOMMIT) .
endif

oci-archive: docker
	skopeo copy docker-daemon:$(DOCKER_REGISTRY)isecl/shvs:$(VERSION)-$(GITCOMMIT) oci-archive:out/shvs-$(VERSION)-$(GITCOMMIT).tar

k8s: oci-archive
	cp -r dist/k8s out/k8s

shvs-docker-push: docker
	docker tag $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)-$(GITCOMMIT) $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)
	docker push $(DOCKER_REGISTRY)isecl/shvs:$(VERSION)-$(GITCOMMIT)


all: clean installer k8s

clean:
	rm -f cover.*
	rm -rf out/
