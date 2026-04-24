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

/// Public marketing landing — the FIRST thing a non-operator sees.
/// CF-Access-bypassed at `/about` so it works without login. Centers
/// on the new deployment model: two product modes (customer-deploy
/// vs confidential), the taint trust model, and the forkable
/// Sats-for-Compute example operator.
pub fn about_page() -> String {
    // Standalone shell (different nav and accent vs the operator
    // dashboard). Inline CSS overrides only what's not already in
    // CSS so the page reads like marketing rather than ops.
    let extra_css = r#"
        body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
        main { max-width: 920px; }
        h1.hero { font-size: 36px; line-height: 1.2; color: #cdd6f4; margin: 32px 0 8px; }
        .lede { color: #a6adc8; font-size: 18px; max-width: 720px; margin-bottom: 32px; }
        h2 { color: #89b4fa; font-size: 22px; margin: 32px 0 12px; }
        p { color: #cdd6f4; font-size: 15px; line-height: 1.6; margin-bottom: 12px; }
        ul { color: #cdd6f4; font-size: 15px; line-height: 1.7; margin: 0 0 16px 24px; }
        ul li { margin-bottom: 4px; }
        .modes { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0 24px; }
        .mode { background: #181825; border: 1px solid #313244; border-radius: 8px; padding: 20px; }
        .mode h3 { color: #cba6f7; font-size: 17px; margin-bottom: 8px; }
        .mode .tag { display: inline-block; background: #cba6f722; color: #cba6f7; font-size: 11px; padding: 2px 8px; border-radius: 4px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
        .mode.confidential h3 { color: #fab387; }
        .mode.confidential .tag { background: #fab38722; color: #fab387; }
        table.taint { margin: 12px 0 24px; }
        table.taint td { vertical-align: top; }
        table.taint td code { white-space: nowrap; }
        .footer { color: #585b70; font-size: 13px; margin-top: 48px; padding-top: 16px; border-top: 1px solid #313244; }
        .footer a { color: #89b4fa; }
        @media (max-width:640px) { .modes { grid-template-columns: 1fr; } h1.hero { font-size: 28px; } }
    "#;
    let body = r##"
<h1 class="hero">Attested compute, two ways to use it.</h1>
<p class="lede">
DevOpsDefender hosts workloads inside Intel TDX confidential VMs. Every node ships an
Intel-signed quote on <code>/health</code>; you can verify what's running before you trust it.
Customers get full <code>/deploy</code> authority — or pay for a sealed oracle nobody (not even
the operator) can change.
</p>

<h2>Two product modes</h2>
<div class="modes">
  <div class="mode">
    <span class="tag">customer deploy</span>
    <h3>Bring your own workload</h3>
    <p>
      The customer's GitHub OIDC identity is bound to a fresh agent via <code>POST /owner</code>.
      They get full <code>/deploy</code>, <code>/exec</code>, <code>/logs</code>, and
      browser-shell (<code>ttyd</code>) authority — the same surface DD ops uses, scoped to their
      org for the duration of the claim.
    </p>
    <p>Right for: general-purpose compute, dev shells, GPU jobs.</p>
  </div>
  <div class="mode confidential">
    <span class="tag">confidential</span>
    <h3>Sealed oracle</h3>
    <p>
      The bot deploys a workload from the customer's public GitHub repo
      (<code>workload.json</code> at root). The agent boots with
      <code>DD_CONFIDENTIAL=true</code> — <code>/deploy</code>, <code>/exec</code>, and
      <code>/owner</code> are <em>not registered</em> on this node. Logs and attestation stay
      open. The TDX quote measures the boot config, so a third party can verify the workload is
      sealed, no operator-trust needed.
    </p>
    <p>Right for: oracles, bot-oracles, anything where "this is the code, it hasn't changed" is the product.</p>
  </div>
</div>

<h2>Trust model</h2>
<p>
A node is in one of three states. Taint is a <em>set</em> of reasons, not a boolean — third-party
verifiers read <code>/health.taint_reasons</code> + the TDX quote and reconstruct the trust
profile in one fetch.
</p>
<table class="taint">
  <tr>
    <td><span class="pill healthy">pristine</span></td>
    <td>Booted from a known image. No customer has had deploy / exec / shell authority.
        Empty <code>taint_reasons</code> set.</td>
  </tr>
  <tr>
    <td><span class="pill stale">tainted</span></td>
    <td>Customer-influenced via at least one channel. Reasons surface which:</td>
  </tr>
  <tr>
    <td></td>
    <td>
      <ul>
        <li><code>customer_workload_deployed</code> — a <code>/deploy</code> succeeded since boot</li>
        <li><code>customer_owner_enabled</code> — <code>/owner</code> set a non-fleet tenant</li>
        <li><code>arbitrary_exec_enabled</code> — node booted with <code>/deploy</code> + <code>/exec</code> registered (i.e. not confidential mode)</li>
        <li><code>interactive_shell_enabled</code> — ttyd or equivalent in the running workload</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td><span class="pill idle">safe_mode</span></td>
    <td>On reboot, the agent's runtime owner clears and the node returns to bot/DD control.
        It may still be tainted; safe_mode is not the same as pristine. A tainted node is
        rebuilt before reassignment.</td>
  </tr>
</table>

<h2>Sats for Compute — the canonical example operator</h2>
<p>
Pay BTC, get attested compute. The bot creates a GitHub-issue claim, watches for a 1-conf
payment via mempool.space, then either hands a fresh agent to the customer's GitHub org
(customer-deploy mode) or boots a sealed oracle from their public workload repo (confidential
mode). Code is forkable; anyone can run their own operator with their own substrate.
</p>
<ul>
  <li><a href="https://github.com/satsforcompute/satsforcompute" target="_blank">satsforcompute/satsforcompute</a> — the bot</li>
  <li><a href="https://github.com/devopsdefender/dd/blob/main/SATS_FOR_COMPUTE_SPEC.md" target="_blank">SATS_FOR_COMPUTE_SPEC.md</a> — the design doc</li>
</ul>

<h2>Run your own</h2>
<p>
DD is a substrate, not a service. Forking an operator means:
</p>
<ul>
  <li>Stand up your own DD fleet (GCP image, libvirt on baremetal, or Azure CVM)</li>
  <li>Pick a <code>DD_OWNER</code> trust ring (a GH org, a specific repo, an OIDC subject regex)</li>
  <li>Run a Sats-for-Compute-style bot — or your own — that calls <code>POST /owner</code> via your operator-ops repo's GH Actions OIDC</li>
</ul>
<ul>
  <li><a href="https://github.com/devopsdefender/dd" target="_blank">devopsdefender/dd</a> — the substrate</li>
  <li><a href="https://github.com/easyenclave/easyenclave" target="_blank">easyenclave/easyenclave</a> — the TDX VM image DD nodes boot from</li>
</ul>

<div class="footer">
  Operator dashboard: <a href="/">app.devopsdefender.com</a> (CF-Access gated).<br/>
  Health + Noise pre-handshake bundle: <a href="/health"><code>/health</code></a> (public).
</div>
"##;

    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevOpsDefender — attested compute</title>
<style>{CSS}{extra_css}</style></head>
<body>
<nav><span class="brand">DevOpsDefender</span>
<a href="/about" class="active">About</a>
<a href="/">Dashboard</a>
<a href="https://github.com/devopsdefender/dd" target="_blank">GitHub</a>
<span class="spacer"></span>
</nav>
<main>{body}</main>
</body></html>"#
    )
}
