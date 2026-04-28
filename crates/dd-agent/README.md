# dd-agent

Minimal DD agent for the v2 ownership model.

This crate implements the new product primitive directly:

- public `GET /health` proof document
- idempotent runtime assignment via `POST /owner`
- current-owner-only workload deployment via `POST /deploy`
- current-owner-only logs via `GET /logs/{app}`
- optional current-owner-only exec via `POST /exec`

It is not the finished confidential runtime. It is the smallest executable
shape for validating ownership and external-repo deployment before porting TDX,
EasyEnclave, ingress, and CP reconciliation code.

## Run

```bash
DD_ASSIGNMENT_AUTHORITY_KIND=repo \
DD_ASSIGNMENT_AUTHORITY_NAME=example/assigner \
DD_ASSIGNMENT_AUTHORITY_ID=123456789 \
cargo run -p dd-agent
```

The assignment authority is the GitHub principal allowed to call `/owner`.
The current owner set by `/owner` is the only principal allowed to call
`/deploy`, `/logs/{app}`, and `/exec`.
