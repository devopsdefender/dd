import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { viteSingleFile } from "vite-plugin-singlefile";

// Single-file output: Vite inlines the hashed JS/CSS into one
// `dist/index.html` so the Rust side can `include_str!` it unchanged.
// Avoids an asset handler on the server and keeps the bastion binary
// self-contained.
export default defineConfig({
  plugins: [svelte(), viteSingleFile()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
});
