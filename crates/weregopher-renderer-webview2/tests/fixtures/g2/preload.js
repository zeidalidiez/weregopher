(() => {
  "use strict";

  const documentStartedWhileLoading = document.readyState === "loading";
  const channel = "__weregopher_g2_v1";
  Object.defineProperty(globalThis, "__weregopherG2IsolatedWorld", {
    value: Object.freeze({ ready: true }),
    writable: false,
    configurable: false,
  });

  window.addEventListener("message", (event) => {
    if (event.source !== window || typeof event.data !== "string") return;
    let request;
    try {
      request = JSON.parse(event.data);
    } catch {
      return;
    }
    if (request.channel !== channel || request.kind !== "call") return;
    const activeHandle = window.sessionStorage.getItem(
      "__weregopher_g2_active_handle",
    );
    const response =
      request.handle === activeHandle
        ? {
            channel,
            kind: "result",
            id: request.id,
            value: `isolated:${request.value}`,
          }
        : {
            channel,
            kind: "result",
            id: request.id,
            error: "stale handle",
          };
    window.postMessage(
      JSON.stringify(response),
      window.location.origin,
    );
  });

  window.addEventListener("DOMContentLoaded", () => {
    const checks = {
      document_start: documentStartedWhileLoading,
      isolated_globals:
        typeof globalThis.__weregopherG2PageWorld === "undefined",
      prototype_isolation:
        typeof Object.prototype.pollutedByPage === "undefined",
    };
    document.documentElement.setAttribute(
      "data-weregopher-g2-isolated",
      JSON.stringify(checks),
    );
  });
})();
