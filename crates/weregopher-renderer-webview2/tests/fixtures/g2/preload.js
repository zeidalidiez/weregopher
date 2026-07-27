(() => {
  "use strict";

  const documentStartedWhileLoading = document.readyState === "loading";
  const eventPrefix = "__weregopher_g2_";
  Object.defineProperty(globalThis, "__weregopherG2IsolatedWorld", {
    value: Object.freeze({ ready: true }),
    writable: false,
    configurable: false,
  });

  window.addEventListener(`${eventPrefix}call`, (event) => {
    if (typeof event.detail !== "string") return;
    const request = JSON.parse(event.detail);
    const activeHandle = window.sessionStorage.getItem(
      `${eventPrefix}active_handle`,
    );
    const response =
      request.handle === activeHandle
        ? { id: request.id, value: `isolated:${request.value}` }
        : { id: request.id, error: "stale handle" };
    window.dispatchEvent(
      new CustomEvent(`${eventPrefix}result`, {
        detail: JSON.stringify(response),
      }),
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
