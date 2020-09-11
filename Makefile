SHELL := /bin/bash
GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
.PHONY: cms installer docker all test clean

cms:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/cms/v3/version.BuildDate=$(BUILDDATE) -X intel/isecl/cms/v3/version.Version=$(VERSION) -X intel/isecl/cms/v3/version.GitHash=$(GITCOMMIT)" -o out/cms

installer: cms
	mkdir -p out/installer
	cp dist/linux/cms.service out/installer/cms.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/cms out/installer/cms
	makeself out/installer out/cms-$(VERSION).bin "Certificate Management Service $(VERSION)" ./install.sh

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.16/swagger-codegen-cli-3.0.16.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc: 
	mkdir -p out/swagger
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
ifeq ($(PROXY_EXISTS),1)
	docker build -t isecl/cms:$(VERSION) --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -f ./dist/docker/Dockerfile ./out
else
	docker build -t isecl/cms:$(VERSION) -f ./dist/docker/Dockerfile ./out
endif
	docker save isecl/cms:$(VERSION) > ./out/docker-cms-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-cms
	cp dist/docker/docker-compose.yml out/docker-cms/docker-compose
	cp dist/docker/entrypoint.sh out/docker-cms/entrypoint.sh && chmod +x out/docker-cms/entrypoint.sh
	cp dist/docker/README.md out/docker-cms/README.md
	cp out/cms-$(VERSION).bin out/docker-cms/cms-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-cms/Dockerfile
	zip -r out/docker-cms.zip out/docker-cms	

all: clean installer

clean:
	rm -f cover.*
	rm -f cms
	rm -rf out/
