(() => {
  "use strict";

  const channel = "__weregopher_g2_v1";
  const priorHandle = window.sessionStorage.getItem(
    "__weregopher_g2_active_handle",
  );
  const priorGeneration = Number(
    window.sessionStorage.getItem("__weregopher_g2_generation") || "0",
  );
  const generation = priorGeneration + 1;
  const activeHandle = `generation-${generation}`;
  window.sessionStorage.setItem(
    "__weregopher_g2_generation",
    String(generation),
  );
  window.sessionStorage.setItem("__weregopher_g2_active_handle", activeHandle);

  const pending = new Map();
  let nextRequest = 1;
  window.addEventListener("message", (event) => {
    if (event.source !== window || typeof event.data !== "string") return;
    let response;
    try {
      response = JSON.parse(event.data);
    } catch {
      return;
    }
    if (response.channel !== channel || response.kind !== "result") return;
    const callbacks = pending.get(response.id);
    if (!callbacks) return;
    pending.delete(response.id);
    window.clearTimeout(callbacks.timeout);
    if (response.error) callbacks.reject(new Error(response.error));
    else callbacks.resolve(response.value);
  });

  const invokeHandle = (handle, value) =>
    new Promise((resolve, reject) => {
      const id = nextRequest++;
      const timeout = window.setTimeout(() => {
        pending.delete(id);
        const marker = document.documentElement.getAttribute(
          "data-weregopher-g2-isolated",
        );
        reject(
          new Error(
            `isolated response timeout; marker=${marker ?? "missing"}`,
          ),
        );
      }, 5000);
      pending.set(id, { resolve, reject, timeout });
      // This synthetic transport carries no authority; the listener also
      // requires same-window, channel-tagged JSON.
      window.postMessage(
        JSON.stringify({ channel, kind: "call", id, handle, value }),
        "*",
      );
    });

  const version = Object.freeze({ major: 1, profile: "synthetic-g2" });
  const projection = Object.freeze({
    version,
    echo: (value) => invokeHandle(activeHandle, value),
    probePriorInvalidation: async () => {
      if (priorHandle === null) return null;
      try {
        await invokeHandle(priorHandle, "stale");
        return false;
      } catch (error) {
        return error instanceof Error && error.message === "stale handle";
      }
    },
  });
  Object.defineProperty(window, "desktop", {
    value: projection,
    writable: false,
    configurable: false,
    enumerable: true,
  });
  Object.defineProperty(globalThis, "__weregopherG2MainWorld", {
    value: true,
    writable: false,
    configurable: false,
  });
})();
