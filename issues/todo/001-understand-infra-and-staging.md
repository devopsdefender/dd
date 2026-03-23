---
title: Understand and test staging/production infrastructure
priority: high
---

## Description

Get a full picture of the current infrastructure state — what's live, what's legacy, what's broken, and what the deployment pipeline looks like end to end.

## Scope

- Review `infra/` directory — Ansible playbooks, GCP configs, what they do
- Review GitHub Actions workflows in `.github/workflows/` — staging-deploy, production-deploy, release, CI
- Check current staging endpoint: https://app-staging.devopsdefender.com/health
- Check current production endpoint: https://app.devopsdefender.com/health
- Understand the branch strategy — what's on main, what branches exist, what's stale
- Map out: what runs where, what's still easyenclave legacy vs devopsdefender

## Acceptance Criteria

- [ ] Document current state of staging + production (up/down, version, git SHA)
- [ ] List all GitHub Actions workflows and what they do
- [ ] Identify any legacy easyenclave references in infra/Ansible that need updating
- [ ] Write a short `infra/STATUS.md` summarizing findings
- [ ] Commit STATUS.md to the repo
