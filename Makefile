IMAGE := discourse/syslogstash
TAG := $(shell date -u +%Y%m%d.%H%M%S)

.PHONY: default
default: push
	@printf "${IMAGE}:${TAG} ready\n"

.PHONY: push
push: build
	docker push ${IMAGE}:${TAG}

.PHONY: build
build:
	docker build --build-arg=http_proxy=${http_proxy} -t ${IMAGE}:${TAG} .
