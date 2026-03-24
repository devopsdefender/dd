# Infrastructure — KVM VM Deployment on OVH Dedicated Hardware

This directory contains everything needed to deploy DevOps Defender agents as KVM VMs on dedicated OVH servers using Ansible and GitHub Actions. The agent runs inside a QEMU/KVM virtual machine on the OVH host, not directly on the bare metal.

## What the playbook does

`ansible/playbooks/baremetal-agent-deploy.yml` runs against a KVM host and:

1. **Installs prerequisites** — QEMU, cloud-image-utils, and other packages needed to run VMs.
2. **Builds a VM image** — copies the `dd-agent` and `dd-cp` binaries to the host, then runs Packer to bake a qcow2 image with all dependencies pre-installed.
3. **Stops the old VM** — gracefully shuts down any existing agent VM for this environment.
4. **Launches the new VM** — starts a QEMU/KVM VM from the freshly built image, injecting the agent config via cloud-init.

The playbook is idempotent — running it again replaces the VM with a fresh one.

## How the inventory works

Each environment has its own inventory file in `ansible/inventory/`:

```
ansible/inventory/
├── staging.yml      # staging host + environment-specific vars
└── production.yml   # production host + environment-specific vars
```

An inventory file defines **where** to deploy and **what settings** to use:

```yaml
all:
  hosts:
    staging:
      ansible_host: 10.0.0.1          # Target KVM host IP
      ansible_user: ubuntu             # SSH user
      ansible_ssh_private_key_file: ... # SSH key path
  vars:
    dd_env: staging                    # Environment name
    cp_url: "https://app-staging.example.com"  # Control plane URL
    agent_memory: 8G                   # VM memory allocation
    agent_cpus: 4                      # VM CPU count
    agent_node_size: standard          # Workload size class
```

The GitHub Actions workflows reference the inventory file with `-i`, so all host and environment config lives in one place — no inline `-e` overrides for things already in inventory.

## How to add a new environment

1. **Create an inventory file** — copy `staging.yml` to `ansible/inventory/<env>.yml` and update the host IP, user, and vars.

2. **Create a workflow** — copy `.github/workflows/baremetal-staging-deploy.yml` and update:
   - The inventory path: `-i infra/ansible/inventory/<env>.yml`
   - The SSH key secret and host for `ssh-keyscan`
   - The `environment:` field for GitHub environment protection rules
   - The private-llm deploy step (compose file and node size)

3. **Add GitHub secrets** — in the repo's GitHub Settings > Environments, create the new environment and add `BAREMETAL_SSH_KEY`.

4. **Push** — the workflow will pick up the new inventory and deploy.

## How the GitHub Actions workflows trigger

| Workflow | File | Trigger | What it does |
|---|---|---|---|
| **Staging** | `baremetal-staging-deploy.yml` | Push to `main` (agent/cp/images/infra paths), or manual | Build + deploy + private-llm (CPU) |
| **Production** | `baremetal-production-deploy.yml` | Manual dispatch only | Build + deploy + private-llm (H100 GPU) |

Both workflows follow the same pattern:

1. Check out code and build Rust binaries (`cargo build --workspace --release`)
2. Set up SSH key for Ansible to reach the OVH dedicated server
3. Run the `baremetal-agent-deploy.yml` playbook against the environment's inventory
4. Deploy the private-llm example app using the `deploy-to-defender` composite action

Production accepts optional dispatch inputs (`vfio_device`, `agent_memory`, `agent_cpus`) that override inventory defaults for GPU passthrough and resource tuning on the OVH host.

## Directory structure

```
infra/
├── README.md                              # This file
├── STATUS.md                              # Operational status notes
├── ansible/
│   ├── ansible.cfg                        # Ansible config (default inventory, etc.)
│   ├── inventory/
│   │   ├── staging.yml                    # Staging host + vars
│   │   └── production.yml                 # Production host + vars
│   └── playbooks/
│       ├── baremetal-agent-deploy.yml      # Main deploy playbook
│       └── templates/
│           ├── agent.json.j2              # Agent config template
│           └── control-plane.json.j2      # Control-plane config template
└── scripts/
    ├── vm-launch.sh                       # Launch QEMU/KVM VM
    ├── vm-stop.sh                         # Stop VM by name
    └── vm-status.sh                       # List running VMs
```
