<script lang="ts">
  import {
    ui,
    createShell,
    killShell,
    refreshConnectors,
    pickShellConnector,
  } from "../ui.svelte";
  import type { Row } from "../ui.svelte";
  import type { ConnectorKind } from "../connectors";
  import { addDdEnclave } from "../connectors";

  // Rendered in this order; unknown kinds fall into "Other".
  const CATEGORIES: { key: string; label: string }[] = [
    { key: "shell", label: "Shells" },
    { key: "workload", label: "Workloads" },
    { key: "claude", label: "Claude" },
    { key: "codex", label: "Codex" },
  ];

  // Placeholder "+" menu items. Each one names the discovery story
  // so the next PR knows what it's meant to auto-populate:
  // - ssh-host: read ~/.ssh/known_hosts + ~/.ssh/config on the user's
  //   side (web: paste/upload; Tauri: file read).
  // - anthropic: one API key → list conversations via API.
  // - github: one OAuth token → events feed → blocks.
  // - local-shell: Tauri-only native PTY.
  const ADD_OPTIONS: {
    kind: ConnectorKind | "local-shell";
    label: string;
    hint: string;
    enabled: boolean;
  }[] = [
    {
      kind: "dd-enclave",
      label: "Add DD enclave…",
      hint: "By block URL; or let CP discover for you.",
      enabled: true,
    },
    {
      kind: "ssh-host",
      label: "Add SSH host",
      hint: "Discovers from ~/.ssh/known_hosts + ~/.ssh/config.",
      enabled: false,
    },
    {
      kind: "anthropic",
      label: "Add Anthropic conversations",
      hint: "Paste an API key; list conversations via API.",
      enabled: false,
    },
    {
      kind: "github",
      label: "Add GitHub activity",
      hint: "OAuth token → events feed → blocks.",
      enabled: false,
    },
    {
      kind: "local-shell",
      label: "Add local shell",
      hint: "Tauri-only; opens a native PTY on this device.",
      enabled: false,
    },
  ];

  type Grouped = Map<string, [string, Row][]>;

  function groupRows(rows: Map<string, Row>): {
    by: Grouped;
    other: [string, Row][];
  } {
    const by: Grouped = new Map(CATEGORIES.map((c) => [c.key, []]));
    const other: [string, Row][] = [];
    for (const entry of rows) {
      const kind = entry[1].info.kind || "shell";
      const bucket = by.get(kind);
      if (bucket) bucket.push(entry);
      else other.push(entry);
    }
    return { by, other };
  }

  /// Label for a row in the sidebar — connector's label (usually
  /// the agent's vm_name) + the session's title/id. When the user
  /// only has one connector this is a bit verbose, but it's the
  /// right default once they add ssh/anthropic/etc. alongside.
  function rowLabel(row: Row): string {
    const t = row.info.title || row.info.id.slice(0, 8);
    if (ui.connectors.length <= 1) return t;
    return `${row.connector.label} · ${t}`;
  }

  let grouped = $derived(groupRows(ui.rows));
  let menuOpen = $state(false);
  let addingEnclave = $state(false);
  let newEnclaveUrl = $state("");

  async function submitEnclave(e: Event) {
    e.preventDefault();
    if (!newEnclaveUrl.trim()) return;
    try {
      await addDdEnclave(newEnclaveUrl);
      newEnclaveUrl = "";
      addingEnclave = false;
      menuOpen = false;
      await refreshConnectors();
    } catch (err) {
      console.error("add enclave failed:", err);
    }
  }
</script>

<aside class="sidebar">
  <div class="hdr">
    <span class="grow">Sessions</span>
    {#if ui.deviceFp}
      <span class="fp" title="Device identity (first 4 bytes)">
        {ui.deviceFp}
      </span>
    {/if}
    <div class="menu-wrap">
      <button
        class="icon"
        title="New shell / add connector"
        onclick={() => {
          const c = pickShellConnector();
          if (menuOpen) {
            menuOpen = false;
          } else if (c) {
            createShell(c);
          } else {
            menuOpen = true;
          }
        }}
        oncontextmenu={(e) => {
          e.preventDefault();
          menuOpen = !menuOpen;
        }}>+</button>
      {#if menuOpen}
        <div class="menu" role="menu">
          <div class="menu-head">Add connector</div>
          {#each ADD_OPTIONS as opt}
            <button
              class="menu-item"
              class:disabled={!opt.enabled}
              disabled={!opt.enabled}
              title={opt.hint}
              onclick={() => {
                if (opt.kind === "dd-enclave") {
                  addingEnclave = true;
                }
              }}
            >
              {opt.label}
              {#if !opt.enabled}<span class="todo">TODO</span>{/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  {#if addingEnclave}
    <form class="add-form" onsubmit={submitEnclave}>
      <label for="enclave-url">Enclave URL</label>
      <input
        id="enclave-url"
        type="url"
        placeholder="https://dd-…-block.devopsdefender.com"
        bind:value={newEnclaveUrl}
      />
      <div class="add-actions">
        <button type="submit">Add</button>
        <button type="button" onclick={() => { addingEnclave = false; }}>
          Cancel
        </button>
      </div>
    </form>
  {/if}

  <ul class="list">
    {#each CATEGORIES as cat}
      {@const items = grouped.by.get(cat.key) ?? []}
      <li class="cat-hdr">{cat.label}</li>
      {#if items.length === 0}
        <li class="cat-empty">
          {cat.key === "shell" ? "No shells — click + to create one" : "None"}
        </li>
      {:else}
        {#each items as [id, row] (id)}
          <li class="session" class:active={ui.active === id}>
            <div class="ses-row">
              <button
                class="t"
                onclick={() => (ui.active = id)}
                title={rowLabel(row)}>
                {rowLabel(row)}
              </button>
              {#if row.info.kind === "shell"}
                <button
                  class="x"
                  title="Close"
                  onclick={() => killShell(row)}
                  aria-label="Close session">×</button>
              {/if}
            </div>
            {#if row.blocks.length > 0}
              <ul class="blocks">
                {#each row.blocks.slice(-50) as b (b.seq)}
                  <li
                    class={b.exit_code === 0 ? "ok" : "fail"}
                    title={`exit ${b.exit_code}`}>
                    {(b.command || "(no command)").slice(0, 80)}
                  </li>
                {/each}
              </ul>
            {/if}
          </li>
        {/each}
      {/if}
    {/each}
    {#if grouped.other.length > 0}
      <li class="cat-hdr">Other</li>
      {#each grouped.other as [id, row] (id)}
        <li class="session" class:active={ui.active === id}>
          <div class="ses-row">
            <button
              class="t"
              onclick={() => (ui.active = id)}
              title={rowLabel(row)}>
              {rowLabel(row)}
            </button>
          </div>
        </li>
      {/each}
    {/if}
  </ul>
</aside>

<style>
  .sidebar {
    width: 300px;
    border-right: 1px solid #313244;
    background: #181825;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .hdr {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 14px;
    border-bottom: 1px solid #313244;
    color: #a6adc8;
    font-size: 12px;
    text-transform: uppercase;
  }
  .hdr .grow { flex: 1; }
  .hdr .fp {
    font-family: ui-monospace, monospace;
    font-size: 10px;
    color: #6c7086;
    padding: 1px 6px;
    border: 1px solid #313244;
    border-radius: 3px;
    letter-spacing: 0.6px;
  }
  button.icon {
    padding: 2px 10px;
    font-size: 16px;
    line-height: 1;
    background: #313244;
    color: #cdd6f4;
    border: 0;
    border-radius: 4px;
    cursor: pointer;
  }
  button.icon:hover { background: #45475a; }
  .menu-wrap { position: relative; }
  .menu {
    position: absolute;
    top: 28px;
    right: 0;
    background: #181825;
    border: 1px solid #313244;
    border-radius: 4px;
    padding: 4px;
    min-width: 220px;
    z-index: 10;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
  }
  .menu-head {
    color: #89b4fa;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 6px 8px 4px;
  }
  .menu-item {
    all: unset;
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 6px 8px;
    border-radius: 3px;
    color: #cdd6f4;
    font-size: 12px;
    cursor: pointer;
    text-transform: none;
    box-sizing: border-box;
  }
  .menu-item:hover:not(.disabled) { background: #313244; }
  .menu-item.disabled {
    color: #585b70;
    cursor: not-allowed;
  }
  .menu-item .todo {
    margin-left: auto;
    font-size: 9px;
    color: #f9e2af;
    background: #45452344;
    padding: 1px 4px;
    border-radius: 2px;
    letter-spacing: 0.4px;
  }
  .add-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 12px 14px;
    background: #1e1e2e;
    border-bottom: 1px solid #313244;
  }
  .add-form label {
    color: #a6adc8;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .add-form input {
    background: #11111b;
    color: #cdd6f4;
    border: 1px solid #313244;
    border-radius: 3px;
    padding: 6px 8px;
    font-size: 12px;
    font-family: ui-monospace, monospace;
  }
  .add-form input:focus {
    outline: none;
    border-color: #89b4fa;
  }
  .add-actions { display: flex; gap: 6px; }
  .add-actions button {
    flex: 1;
    padding: 6px 8px;
    border: 0;
    border-radius: 3px;
    background: #313244;
    color: #cdd6f4;
    font-size: 11px;
    cursor: pointer;
  }
  .add-actions button[type="submit"] { background: #89b4fa; color: #11111b; }
  .list {
    list-style: none;
    margin: 0;
    padding: 6px;
    overflow-y: auto;
    flex: 1;
  }
  .session { margin-bottom: 4px; }
  .ses-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    border-radius: 4px;
    color: #cdd6f4;
    font-size: 13px;
  }
  .ses-row:hover { background: #313244; }
  .session.active > .ses-row { background: #45475a; }
  .ses-row button.t {
    all: unset;
    flex: 1;
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ses-row button.x {
    all: unset;
    color: #6c7086;
    padding: 0 4px;
    font-size: 14px;
    cursor: pointer;
  }
  .ses-row button.x:hover { color: #f38ba8; }
  .blocks {
    list-style: none;
    margin: 0;
    padding: 2px 6px 6px 18px;
  }
  .blocks li {
    font-size: 11px;
    color: #a6adc8;
    padding: 3px 6px;
    border-left: 2px solid #313244;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .blocks li.ok { border-left-color: #a6e3a133; }
  .blocks li.fail { border-left-color: #f38ba888; }
  .cat-hdr {
    color: #89b4fa;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 10px 10px 4px;
    border-bottom: 1px solid #31324466;
    margin-top: 6px;
  }
  .cat-hdr:first-child { margin-top: 0; }
  .cat-empty {
    color: #585b70;
    font-size: 11px;
    font-style: italic;
    padding: 4px 10px 6px;
  }
</style>
