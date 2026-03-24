# Infra Status

KVM VM deployment on dedicated OVH hardware. GCP playbooks were removed (2026-03-23) — all environments now deploy agents as KVM/QEMU VMs on dedicated OVH servers.

## Structure

```
infra/
├── ansible/
│   ├── ansible.cfg                         # Default inventory: staging.yml
│   ├── inventory/
│   │   ├── staging.yml                     # Staging host, vars (memory, cpus, node_size, cp_url)
│   │   └── production.yml                  # Production host, vars (memory, cpus, node_size, cp_url)
│   └── playbooks/
│       ├── baremetal-agent-deploy.yml       # Build image via Packer + deploy agent VM (used by CI)
│       └── templates/
│           ├── agent.json.j2               # Agent config template
│           └── control-plane.json.j2       # Control-plane config template
└── scripts/
    ├── vm-launch.sh                        # Launch QEMU/KVM VM from qcow2 image
    ├── vm-stop.sh                          # Stop VM by name
    └── vm-status.sh                        # List running VMs
```

## Workflows

| Workflow | Trigger | Playbook |
|---|---|---|
| `baremetal-staging-deploy.yml` | Push to main | `baremetal-agent-deploy.yml` |
| `baremetal-production-deploy.yml` | Manual dispatch | `baremetal-agent-deploy.yml` |

## Deploy Flow

1. CI builds `dd-agent` and `dd-cp` binaries
2. Ansible copies binaries + Packer templates to target host
3. Packer builds a qcow2 VM image on the host
4. Old agent VM is stopped and cleaned up
5. New agent VM is launched via `vm-launch.sh`
