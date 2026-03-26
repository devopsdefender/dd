# Infra Status

Current target state:

- Staging control plane: GCP
- Staging bootstrap/test agent: GCP
- Staging example-app VM: OVH host, managed by libvirt and visible in `virsh list`
- Production app VM: OVH host, managed by libvirt and pointed at the external production control plane
- Cloudflare: still active; only stale records/resources were deleted manually

## Structure

```
infra/
├── ansible/
│   ├── ansible.cfg                         # Default inventory: staging.yml
│   ├── inventory/
│   │   ├── staging.yml                     # OVH staging app VM host + external GCP cp_url
│   │   └── production.yml                  # OVH production app VM host + external cp_url
│   └── playbooks/
│       ├── baremetal-agent-deploy.yml      # Bake image + deploy libvirt-managed OVH VM
│       ├── gcp-control-plane-new.yml       # Launch staging control plane on GCP
│       ├── gcp-deploy.yml                  # Launch staging control plane + first GCP agent
│       ├── gcp-image-bake.yml              # Bake GCP image
│       ├── gcp-vm-fleet-new.yml            # Launch GCP agents
│       └── templates/
│           ├── agent-startup.sh.j2         # GCP agent startup metadata
│           └── control-plane-startup.sh.j2 # GCP control-plane startup metadata
└── scripts/
    ├── vm-launch.sh                        # Define/start libvirt VM from qcow2 image
    ├── vm-stop.sh                          # Shutdown + undefine libvirt VM
    └── vm-status.sh                        # Repo VM summary + virsh list --all
```

## Workflows

| Workflow | Trigger | Playbook |
|---|---|---|
| `staging-deploy.yml` | Push to `main` / manual | `gcp-deploy.yml` |
| `baremetal-staging-deploy.yml` | PR / manual | `baremetal-agent-deploy.yml` |
| `baremetal-production-deploy.yml` | Push to `main` / manual | `baremetal-agent-deploy.yml` |

## Deploy Flow

1. `staging-deploy.yml` keeps the control plane and one disposable bootstrap agent on GCP.
2. `baremetal-staging-deploy.yml` keeps the OVH example-app VM aligned with the current branch.
3. `baremetal-production-deploy.yml` does the same for production.
4. OVH VMs are expected to be visible and operable through `virsh list --all`.
