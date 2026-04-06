# Build the confidential VM image with dm-verity.
# Requires: nix develop (or custom image build deps installed)

.PHONY: build clean upload

DD_AGENT_BINARY ?= ../target/x86_64-unknown-linux-musl/release/dd-agent
CLOUDFLARED_URL ?= https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
EXTRA_BIN_DIR := image-extra/usr/local/bin

build: $(EXTRA_BIN_DIR)/dd-agent $(EXTRA_BIN_DIR)/cloudflared
	sudo ./build.sh

$(EXTRA_BIN_DIR)/dd-agent: $(DD_AGENT_BINARY)
	mkdir -p $(EXTRA_BIN_DIR)
	cp $(DD_AGENT_BINARY) $(EXTRA_BIN_DIR)/dd-agent
	chmod +x $(EXTRA_BIN_DIR)/dd-agent

$(EXTRA_BIN_DIR)/cloudflared:
	mkdir -p $(EXTRA_BIN_DIR)
	curl -fsSL -o $(EXTRA_BIN_DIR)/cloudflared $(CLOUDFLARED_URL)
	chmod +x $(EXTRA_BIN_DIR)/cloudflared

clean:
	rm -rf build image-extra dd-agent-vm.raw dd-agent-vm.raw.zst disk.raw dd-agent-image.tar.gz

# Convert raw disk image to GCP format and upload
upload: build
	@echo "Converting disk image to GCP format..."
	qemu-img convert -f raw -O raw dd-agent-vm.raw disk.raw
	tar -czf dd-agent-image.tar.gz disk.raw
	gsutil cp dd-agent-image.tar.gz gs://$(GCP_PROJECT_ID)-images/dd-agent-image.tar.gz
	gcloud compute images create dd-agent-$(shell date +%s) \
		--source-uri=gs://$(GCP_PROJECT_ID)-images/dd-agent-image.tar.gz \
		--project=$(GCP_PROJECT_ID)
