# Infrastructure

Staging is intentionally split:

1. The staging control plane runs on GCP.
2. The first/bootstrap validation agent also runs on GCP.
3. That first GCP agent is disposable after staging validation.
4. The example app runs on the OVH host inside a libvirt-managed VM.

Cloudflare remains in use for the public staging and production hostnames. Only stale DNS and tunnel resources were cleaned up manually while unwinding the previous staging experiment.

## GCP staging

`.github/workflows/staging-deploy.yml` is the canonical staging control-plane workflow. It:

1. Builds `dd-agent` and `dd-cp`.
2. Bakes the GCP image with Packer.
3. Launches the staging control plane on GCP.
4. Launches exactly one tiny bootstrap/test agent on GCP.
5. Smoke-checks `https://app-staging.devopsdefender.com/health`.

The supporting playbooks live under `infra/ansible/playbooks/gcp-*.yml`.

## OVH app VM

`infra/ansible/playbooks/baremetal-agent-deploy.yml` maintains the OVH VM that the example app targets. It:

1. Installs `libvirt`, `virt-install`, QEMU, and cloud-init tooling.
2. Bakes a qcow2 image on the OVH host.
3. Replaces the old VM with a fresh libvirt-managed VM.
4. Points that VM at the external control plane via `cp_url`.

The VM lifecycle scripts are intentionally `virsh`-centric:

- `infra/scripts/vm-launch.sh`: defines and starts the domain in libvirt.
- `infra/scripts/vm-stop.sh`: shuts down and undefines the domain.
- `infra/scripts/vm-status.sh`: shows the repo-managed VMs and `virsh list --all`.

The expected operator view is `virsh list --all`, not a detached raw `qemu-system-*` process.

## Inventories

`infra/ansible/inventory/staging.yml` is the OVH staging app host and points at the external GCP staging control plane.

`infra/ansible/inventory/production.yml` is the OVH production app host and points at the external production control plane.
