<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { Terminal } from "@xterm/xterm";
  import { FitAddon } from "@xterm/addon-fit";
  import type { BlockRecord } from "../types";
  import { ui } from "../ui.svelte";

  interface Props {
    rowId: string;
  }
  let { rowId }: Props = $props();

  let mount: HTMLDivElement | undefined = $state();
  let onResize: (() => void) | null = null;

  onMount(() => {
    const row = ui.rows.get(rowId);
    if (!row || !mount) return;

    // Reuse an existing Terminal if we already opened this row before;
    // otherwise build one and cache it on the row so reselection
    // doesn't blow away scrollback.
    let term = row.term;
    let fit = row.fit;
    if (!term) {
      term = new Terminal({
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 13,
        theme: { background: "#11111b", foreground: "#cdd6f4" },
        cursorBlink: true,
        scrollback: 5000,
      });
      fit = new FitAddon();
      term.loadAddon(fit);
      row.term = term;
      row.fit = fit;
    }
    mount.innerHTML = "";
    term.open(mount);
    fit!.fit();

    if (!row.ws || row.ws.readyState >= WebSocket.CLOSING) {
      openWs();
    }

    onResize = () => fit?.fit();
    window.addEventListener("resize", onResize);
  });

  onDestroy(() => {
    if (onResize) window.removeEventListener("resize", onResize);
  });

  function openWs() {
    const row = ui.rows.get(rowId);
    if (!row) return;
    const term = row.term!;
    const proto = row.agent.origin.startsWith("https:") ? "wss:" : "ws:";
    const base = row.agent.origin.replace(/^https?:/, proto);
    const ws = new WebSocket(`${base}/ws/${row.info.id}`);
    ws.binaryType = "arraybuffer";
    row.ws = ws;

    ws.onopen = () => {
      const haveUpTo = row.blocks.length
        ? row.blocks[row.blocks.length - 1].seq
        : -1;
      ws.send(JSON.stringify({ type: "hello", have_up_to: haveUpTo }));
      ws.send(
        JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows })
      );
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        let msg: { type: string } & Record<string, unknown>;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          return;
        }
        if (msg.type === "block") {
          const b = msg as unknown as BlockRecord;
          if (!row.blocks.some((x) => x.seq === b.seq)) {
            row.blocks = [...row.blocks, b];
          }
        } else if (msg.type === "exit") {
          term.writeln(`\r\n\x1b[2m[exited ${msg.code}]\x1b[0m`);
        }
      } else {
        term.write(new Uint8Array(ev.data as ArrayBuffer));
      }
    };

    term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(d));
      }
    });
    term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    });
  }
</script>

<div class="term" bind:this={mount}></div>

<style>
  .term {
    flex: 1;
    padding: 8px;
    min-height: 0;
  }
</style>
