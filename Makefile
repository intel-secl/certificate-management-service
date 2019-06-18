GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: cms installer docker all test clean

cms:
	env GOOS=linux go build -ldflags "-X intel/isecl/cms/version.Version=$(VERSION) -X intel/isecl/cms/version.GitHash=$(GITCOMMIT)" -o out/cms

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html


installer: cms
	mkdir -p out/installer
	cp dist/linux/cms.service out/installer/cms.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp out/cms out/installer/cms
	makeself out/installer out/cms-$(VERSION).bin "Certificate Management Service $(VERSION)" ./install.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/cms:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/cms:latest > ./out/docker-cms-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-cms
	cp dist/docker/docker-compose.yml out/docker-cms/docker-compose
	cp dist/docker/entrypoint.sh out/docker-cms/entrypoint.sh && chmod +x out/docker-cms/entrypoint.sh
	cp dist/docker/README.md out/docker-cms/README.md
	cp out/cms-$(VERSION).bin out/docker-cms/cms-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-cms/Dockerfile
	zip -r out/docker-cms.zip out/docker-cms	

all: test docker

clean:
	rm -f cover.*
	rm -f cms
	rm -rf out/