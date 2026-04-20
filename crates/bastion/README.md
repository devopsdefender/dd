# bastion

> Block-aware web terminal. Persistent shells, OSC 133 command
> segmentation, `{command, output, exit}` sidebar blocks, xterm.js
> front-end. Mount it in any axum app, or `cargo install` and run
> standalone.

Part of [DevOps Defender](https://github.com/devopsdefender/dd)'s
client-first attested-terminal story. Runs anywhere axum runs; the DD
stack is one deployment target among others.

## Status

Early — **v0.1** ships the local block-terminal module. Noise E2E,
multi-node aggregation, and Tauri desktop/mobile apps land in later
releases. See the plan at
`~/.claude/plans/more-and-more-i-modular-pearl.md` if you have it, or
the GitHub project board.

## Standalone use

```sh
cargo install bastion-term
bastion serve --port 7681
```

Then open <http://127.0.0.1:7681/>.

## Embed in an axum app

```rust
use axum::Router;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mgr = bastion::Manager::new();
    let app: Router = Router::new()
        .route("/", axum::routing::get(|| async { "home" }))
        .nest("/term", bastion::router(mgr));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7681").await?;
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
```

Custom HTML chrome:

```rust
let mgr = bastion::Manager::new().with_shell(|title, body| {
    format!("<!doctype html><html><title>{title}</title>\
            <body><h1>my app</h1>{body}</body></html>")
});
```

See `examples/standalone.rs` for a runnable demo.

## Routes

Relative to wherever you mount the router:

| Method | Path                 | Purpose                      |
| ------ | -------------------- | ---------------------------- |
| GET    | `/`                  | SPA HTML                     |
| GET    | `/api/sessions`      | list sessions                |
| POST   | `/api/sessions`      | create a session             |
| DELETE | `/api/sessions/{id}` | kill a session               |
| GET    | `/ws/{id}`           | WebSocket for a session      |

## WebSocket protocol

Client → server:
- binary frames = stdin bytes (forwarded to PTY)
- text JSON `{"type":"resize","cols":N,"rows":N}` | `{"type":"hello","have_up_to":N}`

Server → client:
- binary frames = raw PTY bytes (feed to xterm.js)
- text JSON `{"type":"block",...record}` | `{"type":"exit","code":N}` |
  `{"type":"gap","from":N,"to":N}` | `{"type":"ready","seq":N}`

## How segmentation works

bastion spawns bash (or sh) with
[WezTerm's shell integration](https://github.com/wezterm/wezterm/tree/main/assets/shell-integration)
injected via `--rcfile`. The shell emits
[OSC 133](https://contour-terminal.org/vt-extensions/osc-133-shell-integration/)
sequences (`A`, `B`, `C`, `D`) around prompt / input / command / exit
boundaries. bastion's [`vte`](https://crates.io/crates/vte)-based
parser cuts the byte stream into one `BlockRecord` per command and
emits it to subscribed WebSocket clients alongside the raw PTY bytes.

## License

MIT — see `LICENSE-MIT`.
