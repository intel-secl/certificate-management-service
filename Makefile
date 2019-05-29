GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: cms installer all clean

cms: clean
	env GOOS=linux go build -ldflags "-X intel/isecl/cms/version.Version=$(VERSION) -X intel/isecl/cms/version.GitHash=$(GITCOMMIT)" -o out/cms

installer: cms
	mkdir -p out/cert-ms/
	cp dist/linux/install.sh out/cert-ms/install.sh && chmod +x out/cert-ms/install.sh
	cp out/cms out/cert-ms/cms
	makeself out/cert-ms out/cms-$(VERSION).bin "Certificate Management Service $(VERSION)" ./install.sh 

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/cms:latest -f ./dist/docker/Dockerfile ./out
#	docker save isecl/cms:latest > ./out/docker-cms-$(VERSION).tar

all: docker

clean:
	rm -rf out/
