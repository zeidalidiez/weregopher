(() => {
  "use strict";

  const eventPrefix = "__weregopher_g2_";
  const priorHandle = window.sessionStorage.getItem(`${eventPrefix}active_handle`);
  const priorGeneration = Number(
    window.sessionStorage.getItem(`${eventPrefix}generation`) || "0",
  );
  const generation = priorGeneration + 1;
  const activeHandle = `generation-${generation}`;
  window.sessionStorage.setItem(`${eventPrefix}generation`, String(generation));
  window.sessionStorage.setItem(`${eventPrefix}active_handle`, activeHandle);

  const pending = new Map();
  let nextRequest = 1;
  window.addEventListener(`${eventPrefix}result`, (event) => {
    if (typeof event.detail !== "string") return;
    const response = JSON.parse(event.detail);
    const callbacks = pending.get(response.id);
    if (!callbacks) return;
    pending.delete(response.id);
    if (response.error) callbacks.reject(new Error(response.error));
    else callbacks.resolve(response.value);
  });

  const invokeHandle = (handle, value) =>
    new Promise((resolve, reject) => {
      const id = nextRequest++;
      pending.set(id, { resolve, reject });
      window.dispatchEvent(
        new CustomEvent(`${eventPrefix}call`, {
          detail: JSON.stringify({ id, handle, value }),
        }),
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
