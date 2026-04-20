//! Shared page shell + CSS + nav for all rendered HTML.

pub const CSS: &str = r#"
* { box-sizing:border-box; margin:0; padding:0; }
body { background:#1e1e2e; color:#cdd6f4; font-family:'JetBrains Mono',ui-monospace,monospace; }
a { color:#89b4fa; text-decoration:none; } a:hover { text-decoration:underline; }
nav { display:flex; align-items:center; gap:16px; padding:12px 24px; border-bottom:1px solid #313244; }
nav .brand { color:#89b4fa; font-weight:700; font-size:14px; }
nav a { color:#a6adc8; font-size:13px; } nav a:hover, nav a.active { color:#cdd6f4; }
nav .spacer { flex:1; }
main { max-width:1080px; margin:0 auto; padding:24px; }
h1 { color:#89b4fa; font-size:20px; margin-bottom:4px; }
.sub { color:#585b70; font-size:12px; margin-bottom:16px; }
.meta { color:#a6adc8; font-size:13px; margin-bottom:24px; }
.meta .ok { color:#a6e3a1; }
.section { color:#a6adc8; font-size:12px; text-transform:uppercase; margin:20px 0 8px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px; }
.card { background:#181825; border:1px solid #313244; border-radius:8px; padding:16px; }
.card .label { color:#a6adc8; font-size:11px; text-transform:uppercase; }
.card .value { font-size:20px; margin-top:4px; }
.card .value.green { color:#a6e3a1; } .card .value.blue { color:#89b4fa; }
.card .value.peach { color:#fab387; } .card .value.mauve { color:#cba6f7; }
.row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #313244; }
.row:last-child { border-bottom:none; }
table { border-collapse:collapse; width:100%; }
th { text-align:left; color:#a6adc8; font-weight:normal; font-size:12px; text-transform:uppercase; padding:8px 12px; border-bottom:1px solid #313244; }
td { padding:8px 12px; border-bottom:1px solid #313244; font-size:14px; }
.pill { display:inline-block; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
.pill.healthy, .pill.running { background:#a6e3a122; color:#a6e3a1; }
.pill.stale, .pill.deploying { background:#fab38722; color:#fab387; }
.pill.dead, .pill.failed, .pill.exited { background:#f38ba822; color:#f38ba8; }
.pill.idle { background:#31324488; color:#a6adc8; }
input, button { font-family:inherit; font-size:14px; }
input[type=password], input[type=text] { width:100%; padding:10px 12px; background:#11111b; border:1px solid #313244; border-radius:6px; color:#cdd6f4; outline:none; }
input:focus { border-color:#89b4fa; }
button { padding:10px 16px; background:#89b4fa; color:#1e1e2e; border:none; border-radius:6px; font-weight:600; cursor:pointer; }
button:hover { background:#74c7ec; }
.empty { color:#585b70; padding:24px; text-align:center; }
.dim { color:#585b70; }
.back { font-size:13px; margin-bottom:20px; }
.err { color:#f38ba8; font-size:13px; margin-bottom:12px; }
pre { background:#11111b; border:1px solid #313244; border-radius:8px; padding:16px; overflow:auto; font-size:12px; line-height:1.5; color:#a6adc8; }
code { background:#11111b; padding:2px 6px; border-radius:3px; font-size:12px; }
@media (max-width:640px) { main { padding:16px; } .cards { grid-template-columns:1fr 1fr; } }
"#;

pub fn shell(title: &str, nav: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{CSS}</style></head><body>{nav}<main>{body}</main></body></html>"#
    )
}

/// Same page frame but the body lives outside the 1080px-capped `<main>`.
/// Used by the terminal page where xterm.js wants the full viewport.
pub fn shell_fullwidth(title: &str, nav: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{CSS}
html,body {{ height:100%; }}
body {{ display:flex; flex-direction:column; }}
.fullpage {{ flex:1; min-height:0; display:flex; }}
</style></head><body>{nav}<div class="fullpage">{body}</div></body></html>"#
    )
}

pub fn nav(items: &[(&str, &str, bool)]) -> String {
    let mut s = String::from(r#"<nav><span class="brand">DD</span>"#);
    for (label, href, active) in items {
        let class = if *active { r#" class="active""# } else { "" };
        s.push_str(&format!(r#"<a href="{href}"{class}>{label}</a>"#));
    }
    // Log out is handled at the edge via CF Access
    // (https://<domain>/cdn-cgi/access/logout). We don't own auth, so
    // we don't render a log-out button in the nav.
    s.push_str(r#"<span class="spacer"></span></nav>"#);
    s
}

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
