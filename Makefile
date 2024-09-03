.PHONY: dev release release-test

dev:
	@go run .

release:
	@mkdir -p release/latest
	@docker build -t dns-hijack-check-action-build -f Dockerfile.build .
	@docker create -ti --name dns-hijack-check-action-build dns-hijack-check-action-build bash 
	@docker cp dns-hijack-check-action-build:/dns-hijack-check-action release/latest/dns-hijack-check-action
	@docker rm -f dns-hijack-check-action-build

release-test:
	@mkdir -p release/latest
	@docker build -t dns-hijack-check-action-build -f Dockerfile.build .
	@docker create -ti --name dns-hijack-check-action-build dns-hijack-check-action-build bash 
	@docker cp dns-hijack-check-action-build:/dns-hijack-check-action release/latest/dns-hijack-check-action-test
	@docker rm -f dns-hijack-check-action-build