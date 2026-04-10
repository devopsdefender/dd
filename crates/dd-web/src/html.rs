/// Catppuccin Mocha CSS theme.
pub const CATPPUCCIN_CSS: &str = r#"
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#1e1e2e; color:#cdd6f4; font-family:'JetBrains Mono',ui-monospace,monospace; }
  a { color:#89b4fa; text-decoration:none; } a:hover { text-decoration:underline; }
  nav { display:flex; align-items:center; gap:16px; padding:12px 24px; border-bottom:1px solid #313244; }
  nav .brand { color:#89b4fa; font-weight:700; font-size:14px; }
  nav a { color:#a6adc8; font-size:13px; } nav a:hover, nav a.active { color:#cdd6f4; }
  nav .spacer { flex:1; }
  main { max-width:960px; margin:0 auto; padding:24px; }
  h1 { color:#89b4fa; font-size:20px; margin-bottom:4px; }
  .sub { color:#585b70; font-size:12px; margin-bottom:16px; }
  .meta { color:#a6adc8; font-size:13px; margin-bottom:24px; }
  .meta .ok { color:#a6e3a1; }
  .section { color:#a6adc8; font-size:12px; text-transform:uppercase; margin:20px 0 8px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:#181825; border:1px solid #313244; border-radius:8px; padding:16px; }
  .card .label { color:#a6adc8; font-size:11px; text-transform:uppercase; }
  .card .value { font-size:20px; margin-top:4px; }
  .card .value.green { color:#a6e3a1; }
  .card .value.blue { color:#89b4fa; }
  .card .value.peach { color:#fab387; }
  .card .value.mauve { color:#cba6f7; }
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
  .empty { color:#585b70; padding:24px; text-align:center; }
  .dim { color:#585b70; }
  .back { font-size:13px; margin-bottom:20px; }
  @media(max-width:640px) { main { padding:16px; } .cards { grid-template-columns:1fr 1fr; } }
"#;

/// Wrap content in a full HTML page with CSS and nav.
pub fn page_shell(title: &str, nav_html: &str, content: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{css}</style></head><body>
{nav}
<main>{content}</main>
</body></html>"#,
        title = title,
        css = CATPPUCCIN_CSS,
        nav = nav_html,
        content = content,
    )
}

/// Build a navigation bar with the given items and a logout link.
pub fn nav_bar(items: &[(&str, &str, bool)]) -> String {
    let mut html = String::from(r#"<nav><span class="brand">DD</span>"#);
    for (label, href, active) in items {
        if *active {
            html.push_str(&format!(r#"<a href="{href}" class="active">{label}</a>"#));
        } else {
            html.push_str(&format!(r#"<a href="{href}">{label}</a>"#));
        }
    }
    html.push_str(r#"<span class="spacer"></span><a href="/auth/logout">log out</a></nav>"#);
    html
}

/// Format seconds as a human-readable uptime string.
pub fn format_uptime(secs: u64) -> String {
    if secs > 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs > 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}
