"use strict";

const bridgeAtApplicationStart =
  typeof window.desktop === "object" &&
  typeof window.desktop.echo === "function";
Object.defineProperty(globalThis, "__weregopherG2PageWorld", {
  value: true,
  configurable: true,
});
Object.defineProperty(Object.prototype, "pollutedByPage", {
  value: "page-only",
  configurable: true,
});

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const isolated = JSON.parse(
      document.documentElement.getAttribute(
        "data-weregopher-g2-isolated",
      ) || "{}",
    );
    const result = await window.desktop.echo("from-page");
    const navigationInvalidation =
      await window.desktop.probePriorInvalidation();
    const descriptor = Object.getOwnPropertyDescriptor(window, "desktop");
    window.chrome.webview.postMessage({
      kind: "g2_preload_observation",
      generation: Number(
        window.sessionStorage.getItem("__weregopher_g2_generation"),
      ),
      round_trip_value: result,
      checks: {
        document_start:
          bridgeAtApplicationStart && isolated.document_start === true,
        isolated_globals:
          typeof globalThis.__weregopherG2IsolatedWorld === "undefined" &&
          isolated.isolated_globals === true,
        prototype_isolation: isolated.prototype_isolation === true,
        frozen_projection:
          Object.isFrozen(window.desktop) &&
          Object.isFrozen(window.desktop.version) &&
          descriptor?.writable === false &&
          descriptor?.configurable === false,
        function_round_trip: result === "isolated:from-page",
        navigation_invalidation: navigationInvalidation === true,
      },
    });
  } catch (error) {
    window.chrome.webview.postMessage({
      kind: "g2_preload_failure",
      message: String(error),
    });
  } finally {
    delete Object.prototype.pollutedByPage;
    delete globalThis.__weregopherG2PageWorld;
  }
});
