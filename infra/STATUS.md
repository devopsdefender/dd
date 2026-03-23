# Infrastructure Status

_Last updated: 2026-03-23_

## Endpoints

| Environment | URL | Status | Git SHA |
|-------------|-----|--------|---------|
| Staging | https://app-staging.devopsdefender.com/health | ✅ UP | `36264e7d` |
| Production | https://app.devopsdefender.com/health | ✅ UP | `16cb8f72` |

Note: staging and production are running **different git SHAs** — production is behind staging.

## GitHub Actions Workflows

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Push/PR | cargo check, test, fmt, clippy |
| `release.yml` | Tag push | Builds binaries + GitHub release |
| `staging-deploy.yml` | Push to main | GCP: build → bake image → deploy → smoke check |
| `baremetal-staging-deploy.yml` | Manual | Bare metal staging deploy via Ansible |
| `baremetal-production-deploy.yml` | Manual | Bare metal production deploy via Ansible |
| `website.yml` | Push to main (website/) | GitHub Pages deployment |
| `website-preview.yml` | Push to wip/* or PR | Preview deploy to GitHub Pages |

## Infra Directory

```
infra/
├── ansible/
│   ├── ansible.cfg
│   ├── inventory/
│   └── playbooks/
│       ├── gcp-control-plane-new.yml   — Launch TDX GCP VM for control plane
│       ├── gcp-vm-fleet-new.yml        — Launch agent fleet on GCP
│       ├── gcp-deploy.yml              — Deploy to existing GCP fleet
│       ├── gcp-cleanup-managed-vms.yml — Tear down old VMs
│       ├── gcp-image-bake.yml          — Build GCP VM images
│       ├── baremetal-deploy.yml        — Bare metal deploy
│       └── baremetal-agent-deploy.yml  — Bare metal agent deploy
└── scripts/
```

## Branch State

- `main` — 4 commits, clean
- `wip/website-copy-rewrite` — active draft PR #1

## Legacy Audit

- ✅ No `easyenclave` references found in Rust code, Ansible, or workflows
- ✅ Clean fork — devopsdefender branding throughout

## Action Items

- [ ] Staging SHA (`36264e7d`) vs production SHA (`16cb8f72`) — determine if production needs a deploy
- [ ] Verify GCP inventory is populated and agents are registered
- [ ] Test a full deployment cycle on staging end-to-end
