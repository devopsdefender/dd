<script lang="ts">
  import { onMount } from "svelte";
  import Sidebar from "./lib/Sidebar.svelte";
  import TerminalPane from "./lib/TerminalPane.svelte";
  import { ui, loadSessions } from "./ui.svelte";

  onMount(loadSessions);
</script>

<div class="page">
  <Sidebar />
  <main class="pane">
    {#if ui.active}
      {#key ui.active}
        <TerminalPane rowId={ui.active} />
      {/key}
    {:else}
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
