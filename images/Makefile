# Build the confidential VM image with dm-verity.
# Requires: nix develop (or mkosi + deps installed)

.PHONY: build clean upload

DD_AGENT_BINARY ?= ../target/release/dd-agent

build: mkosi.extra/usr/local/bin/dd-agent
	sudo mkosi

mkosi.extra/usr/local/bin/dd-agent: $(DD_AGENT_BINARY)
	mkdir -p mkosi.extra/usr/local/bin
	cp $(DD_AGENT_BINARY) mkosi.extra/usr/local/bin/dd-agent
	chmod +x mkosi.extra/usr/local/bin/dd-agent

clean:
	sudo mkosi clean
	rm -rf mkosi.extra mkosi.cache

# Convert raw disk image to GCP format and upload
upload:
	@echo "Converting disk image to GCP format..."
	qemu-img convert -f raw -O raw image.raw disk.raw
	tar -czf dd-agent-image.tar.gz disk.raw
	gsutil cp dd-agent-image.tar.gz gs://$(GCP_PROJECT_ID)-images/dd-agent-image.tar.gz
	gcloud compute images create dd-agent-$(shell date +%s) \
		--source-uri=gs://$(GCP_PROJECT_ID)-images/dd-agent-image.tar.gz \
		--project=$(GCP_PROJECT_ID)
