<script lang="ts">
  import { onMount } from "svelte";
  import Sidebar from "./lib/Sidebar.svelte";
  import TerminalPane from "./lib/TerminalPane.svelte";
  import { ui, loadSessions } from "./ui.svelte";

  onMount(loadSessions);

  // Snapshot the row IDs — iterating the Map directly in `{#each}`
  // creates new [key, value] tuples every render and defeats keyed
  // reconciliation. Pulling ids into a plain array lets Svelte keep
  // each <TerminalPane> alive across re-renders.
  let rowIds = $derived(Array.from(ui.rows.keys()));
</script>

<div class="page">
  <Sidebar />
  <main class="pane">
    {#each rowIds as id (id)}
      <div class="slot" class:active={ui.active === id}>
        <TerminalPane rowId={id} />
      </div>
    {/each}
    {#if !ui.active}
      <div class="empty">No session selected.</div>
    {/if}
  </main>
</div>

<style>
  :global(html, body) {
    height: 100%;
    margin: 0;
    background: #1e1e2e;
    color: #cdd6f4;
    font-family: "JetBrains Mono", ui-monospace, monospace;
  }
  :global(*) {
    box-sizing: border-box;
  }
  .page {
    display: flex;
    height: 100%;
    min-height: 0;
  }
  .pane {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    background: #11111b;
    position: relative;
  }
  /*
   * Keep every row's <TerminalPane> mounted — xterm.js doesn't like
   * being .open()'d twice into different DOM nodes, so once a
   * Terminal is bound to its slot we leave it there and just toggle
   * visibility. Clicking between rows becomes free: no mount/unmount,
   * no re-attach, scrollback preserved.
   */
  .slot {
    position: absolute;
    inset: 0;
    display: none;
    flex-direction: column;
  }
  .slot.active {
    display: flex;
  }
  .empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #585b70;
    font-size: 13px;
  }
</style>
