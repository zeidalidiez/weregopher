"use strict";

const probeAtApplicationStart = window.__weregopherG2PreloadProbe;
Object.defineProperty(globalThis, "__weregopherG2PageWorld", {
  value: true,
  configurable: true,
});
Object.defineProperty(Object.prototype, "pollutedByPage", {
  value: "page-only",
  configurable: true,
});

const failedChecks = () => ({
  document_start: false,
  isolated_globals: false,
  prototype_isolation: false,
  frozen_projection: false,
  function_round_trip: false,
  navigation_invalidation: false,
});

window.addEventListener("DOMContentLoaded", async () => {
  let checks = failedChecks();
  let generation = 0;
  try {
    if (
      probeAtApplicationStart === undefined ||
      typeof probeAtApplicationStart.observe !== "function"
    ) {
      throw new Error("probe bootstrap was not installed at document start");
    }
    generation = probeAtApplicationStart.generation;
    checks = await probeAtApplicationStart.observe();
  } catch {
    // Canonical evidence retains booleans only. Exact source errors and values
    // never cross the WebView2 host-message boundary.
  } finally {
    window.chrome.webview.postMessage({
      kind: "g2_exact_preload_observation",
      generation,
      checks,
    });
    delete Object.prototype.pollutedByPage;
    delete globalThis.__weregopherG2PageWorld;
  }
});
