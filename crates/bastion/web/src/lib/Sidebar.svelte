<script lang="ts">
  import { ui, createShell, killShell } from "../ui.svelte";
  import type { Row } from "../ui.svelte";
  import type { Agent } from "../types";

  // Rendered in this order; unknown kinds fall into "Other".
  const CATEGORIES: { key: string; label: string }[] = [
    { key: "shell", label: "Shells" },
    { key: "workload", label: "Workloads" },
    { key: "claude", label: "Claude" },
    { key: "codex", label: "Codex" },
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

  /// Label for a row in the sidebar. In unified mode, prefix with
  /// the agent's `vm_name` so the user sees which node it lives on.
  function rowLabel(row: Row): string {
    const t = row.info.title || row.info.id.slice(0, 8);
    return ui.unified ? `${row.agent.vm_name} · ${t}` : t;
  }

  function pickNewShellAgent(): Agent {
    // Unified mode: create on the CP itself (first entry of __DD_AGENTS__
    // by convention, since cp.rs puts CP at index 0). Falls back to
    // location.origin in single-node mode.
    return ui.agents[0];
  }

  let grouped = $derived(groupRows(ui.rows));
</script>

<aside class="sidebar">
  <div class="hdr">
    <span class="grow">Sessions</span>
    <button class="icon" title="New shell" onclick={() => createShell(pickNewShellAgent())}>+</button>
  </div>
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
                title={rowLabel(row)}
              >
                {rowLabel(row)}
              </button>
              {#if row.info.kind === "shell"}
                <button
                  class="x"
                  title="Close"
                  onclick={() => killShell(row)}
                  aria-label="Close session"
                >×</button>
              {/if}
            </div>
            {#if row.blocks.length > 0}
              <ul class="blocks">
                {#each row.blocks.slice(-50) as b (b.seq)}
                  <li class={b.exit_code === 0 ? "ok" : "fail"} title={`exit ${b.exit_code}`}>
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
              title={rowLabel(row)}
            >{rowLabel(row)}</button>
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
