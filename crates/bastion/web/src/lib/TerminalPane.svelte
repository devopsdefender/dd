<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { Terminal } from "@xterm/xterm";
  import { FitAddon } from "@xterm/addon-fit";
  import type { BlockRecord } from "../types";
  import { ui } from "../ui.svelte";
  import { openShellTunnel } from "../tunnel";

  interface Props {
    rowId: string;
  }
  let { rowId }: Props = $props();

  let mount: HTMLDivElement | undefined = $state();
  let onResize: (() => void) | null = null;
  let fitRef: FitAddon | null = null;

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
    fitRef = fit!;
    // Initial fit — safe even while slot is hidden; when the slot
    // flips to `display:flex`, the `$effect` below refits against
    // the real dimensions.
    fit!.fit();

    // Open the shell stream if we haven't already. Prefer the Noise
    // tunnel when the connector has a cached server pubkey (cross-
    // origin enclaves); fall back to plain /ws/{id} for same-origin.
    const pubkey = row.connector.config.serverNoisePubkeyHex as
      | string
      | undefined;
    const noiseWanted =
      pubkey && row.origin.replace(/\/+$/, "") !== location.origin;
    if (noiseWanted) {
      if (!row.shell) openNoiseShell();
    } else if (!row.ws || row.ws.readyState >= WebSocket.CLOSING) {
      openWs();
    }

    onResize = () => fit?.fit();
    window.addEventListener("resize", onResize);
  });

  // Re-fit + focus whenever this row becomes the active one. The
  // slot is `display:none` when hidden, so its dimensions are 0×0
  // and any fit done while hidden produces a 0-col terminal. This
  // effect catches the visibility flip and re-measures.
  $effect(() => {
    if (ui.active === rowId && fitRef) {
      // Defer one frame so the CSS layout pass sees the new
      // `.active` class and gives the slot real dimensions.
      queueMicrotask(() => {
        fitRef?.fit();
        const row = ui.rows.get(rowId);
        row?.term?.focus();
      });
    }
  });

  onDestroy(() => {
    if (onResize) window.removeEventListener("resize", onResize);
  });

  function openWs() {
    const row = ui.rows.get(rowId);
    if (!row) return;
    const term = row.term!;
    const proto = row.origin.startsWith("https:") ? "wss:" : "ws:";
    const base = row.origin.replace(/^https?:/, proto);
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

  async function openNoiseShell() {
    const row = ui.rows.get(rowId);
    if (!row) return;
    const term = row.term!;
    const pubkey = row.connector.config.serverNoisePubkeyHex as
      | string
      | undefined;
    if (!pubkey) return;

    let shell;
    try {
      shell = await openShellTunnel(row.origin, pubkey, row.info.id);
    } catch (e) {
      console.warn(`noise-shell: open ${row.origin}/${row.info.id}`, e);
      // Hard fail here — falling back to plain /ws would re-trigger
      // the CORS/CF-Access wall we set up Noise to bypass.
      term.writeln(`\r\n\x1b[2m[tunnel unavailable]\x1b[0m`);
      return;
    }
    row.shell = shell;

    shell.onCtrl((msg) => {
      if (msg.type === "block") {
        const b = msg as unknown as BlockRecord;
        if (!row.blocks.some((x) => x.seq === b.seq)) {
          row.blocks = [...row.blocks, b];
        }
      } else if (msg.type === "exit") {
        term.writeln(`\r\n\x1b[2m[exited ${msg.code}]\x1b[0m`);
      } else if (msg.type === "error" && msg.code === "not_found") {
        term.writeln(`\r\n\x1b[2m[session not found]\x1b[0m`);
      }
    });
    shell.onRaw((bytes) => {
      term.write(bytes);
    });

    shell.sendCtrl({
      type: "hello",
      have_up_to: row.blocks.length
        ? row.blocks[row.blocks.length - 1].seq
        : -1,
    });
    shell.sendCtrl({ type: "resize", cols: term.cols, rows: term.rows });

    term.onData((d) => {
      shell.sendRaw(new TextEncoder().encode(d));
    });
    term.onResize(({ cols, rows }) => {
      shell.sendCtrl({ type: "resize", cols, rows });
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
