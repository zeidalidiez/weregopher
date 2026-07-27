(() => {
  "use strict";
  if (window !== window.top) return;

  const channel = "__weregopher_g2_exact_preload_v1";
  const observationNonce = __WEREGOPHER_OBSERVATION_NONCE__;
  const maxDepth = 16;
  const maxNodes = 4096;
  const maxMessageBytes = 1024 * 1024;
  const bootstrapAtDocumentStart = document.readyState === "loading";
  const priorHandle = window.sessionStorage.getItem(
    "__weregopher_g2_prior_preload_handle",
  );
  const priorGeneration = Number(
    window.sessionStorage.getItem(
      "__weregopher_g2_preload_generation",
    ) || "0",
  );
  const generation =
    Number.isSafeInteger(priorGeneration) && priorGeneration >= 0
      ? priorGeneration + 1
      : 1;
  window.sessionStorage.setItem(
    "__weregopher_g2_preload_generation",
    String(generation),
  );

  const projections = [];
  const installedKeys = new Set();
  const pendingCalls = new Map();
  let nextCall = 1;
  let bridgeFailed = false;
  let completion;
  let resolveCompletion;
  const completionPromise = new Promise((resolve) => {
    resolveCompletion = resolve;
  });

  const post = (payload) => {
    window.postMessage(
      JSON.stringify({ channel, generation, ...payload }),
      "*",
    );
  };

  const rejectDangerousKey = (key) => {
    if (
      key === "__proto__" ||
      key === "prototype" ||
      key === "constructor"
    ) {
      throw new TypeError("unsupported bridge key");
    }
  };

  const decode = (descriptor, depth, budget) => {
    if (
      descriptor === null ||
      typeof descriptor !== "object" ||
      depth > maxDepth
    ) {
      throw new TypeError("invalid bridge descriptor");
    }
    budget.nodes += 1;
    if (budget.nodes > maxNodes) {
      throw new TypeError("bridge descriptor exceeds its node limit");
    }
    switch (descriptor.kind) {
      case "null":
        return null;
      case "undefined":
        return undefined;
      case "boolean":
      case "string":
      case "number":
        return descriptor.value;
      case "function": {
        if (typeof descriptor.handle !== "string") {
          throw new TypeError("invalid function handle");
        }
        return Object.freeze((...args) =>
          invoke(descriptor.handle, args)
        );
      }
      case "array": {
        if (!Array.isArray(descriptor.values)) {
          throw new TypeError("invalid bridge array");
        }
        return Object.freeze(
          descriptor.values.map((value) =>
            decode(value, depth + 1, budget)
          ),
        );
      }
      case "object": {
        if (!Array.isArray(descriptor.entries)) {
          throw new TypeError("invalid bridge object");
        }
        const result = {};
        for (const entry of descriptor.entries) {
          if (
            !Array.isArray(entry) ||
            entry.length !== 2 ||
            typeof entry[0] !== "string"
          ) {
            throw new TypeError("invalid bridge object entry");
          }
          rejectDangerousKey(entry[0]);
          Object.defineProperty(result, entry[0], {
            value: decode(entry[1], depth + 1, budget),
            writable: true,
            configurable: true,
            enumerable: true,
          });
        }
        return Object.freeze(result);
      }
      default:
        throw new TypeError("unsupported bridge descriptor");
    }
  };

  const deeplyFrozen = (value, depth = 0, seen = new Set()) => {
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function")
    ) {
      return true;
    }
    if (depth > maxDepth || seen.has(value) || !Object.isFrozen(value)) {
      return false;
    }
    seen.add(value);
    return Reflect.ownKeys(value).every((key) =>
      deeplyFrozen(value[key], depth + 1, seen)
    );
  };

  const invoke = (handle, args) =>
    new Promise((resolve, reject) => {
      if (
        typeof handle !== "string" ||
        !Array.isArray(args) ||
        pendingCalls.size >= 128
      ) {
        reject(new TypeError("invalid bridge call"));
        return;
      }
      const id = nextCall++;
      const timeout = window.setTimeout(() => {
        pendingCalls.delete(id);
        const error = new Error("bridge call timed out");
        error.code = "timeout";
        reject(error);
      }, 3000);
      pendingCalls.set(id, { resolve, reject, timeout });
      post({ kind: "call", id, handle, args });
    });

  const installProjection = (message) => {
    if (
      typeof message.key !== "string" ||
      message.key.length === 0 ||
      message.key.length > 256 ||
      message.key.startsWith("__weregopher") ||
      installedKeys.has(message.key) ||
      Object.prototype.hasOwnProperty.call(window, message.key)
    ) {
      throw new TypeError("invalid bridge projection key");
    }
    rejectDangerousKey(message.key);
    const projection = decode(message.descriptor, 0, { nodes: 0 });
    Object.defineProperty(window, message.key, {
      value: projection,
      writable: false,
      configurable: false,
      enumerable: true,
    });
    installedKeys.add(message.key);
    projections.push(projection);
  };

  window.addEventListener("message", (event) => {
    if (event.source !== window || typeof event.data !== "string") return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.channel !== channel) return;
    if (message.kind === "isolated_ready") {
      post({ kind: "main_ready" });
      return;
    }
    if (message.generation !== generation) return;
    if (message.kind === "exposure") {
      try {
        installProjection(message);
      } catch {
        bridgeFailed = true;
      }
      return;
    }
    if (message.kind === "complete") {
      completion = {
        documentStart: message.document_start === true,
        exactSourceExecuted: message.exact_source_executed === true,
        exposureCount: Number.isSafeInteger(message.exposure_count)
          ? message.exposure_count
          : 0,
        harnessHandle:
          typeof message.harness_handle === "string"
            ? message.harness_handle
            : "",
      };
      if (completion.harnessHandle.length > 0) {
        window.sessionStorage.setItem(
          "__weregopher_g2_prior_preload_handle",
          completion.harnessHandle,
        );
      }
      resolveCompletion(completion);
      return;
    }
    if (message.kind === "call_result") {
      const pending = pendingCalls.get(message.id);
      if (pending === undefined) return;
      pendingCalls.delete(message.id);
      window.clearTimeout(pending.timeout);
      if (message.ok === true) {
        pending.resolve(message.value);
      } else {
        const error = new Error("isolated bridge call failed");
        error.code =
          typeof message.code === "string" ? message.code : "failed";
        pending.reject(error);
      }
    }
  });

  const observe = async () => {
    const completed = await Promise.race([
      completionPromise,
      new Promise((_, reject) =>
        window.setTimeout(
          () => reject(new Error("preload completion timed out")),
          5000,
        ),
      ),
    ]);
    let current;
    try {
      current = await invoke(completed.harnessHandle, ["from-page"]);
    } catch {
      current = {};
    }
    let navigationInvalidation = false;
    if (priorHandle !== null) {
      try {
        await invoke(priorHandle, ["stale"]);
      } catch (error) {
        navigationInvalidation =
          error instanceof Error && error.code === "stale_handle";
      }
    }
    return {
      document_start:
        bootstrapAtDocumentStart &&
        completed.documentStart &&
        completed.exactSourceExecuted,
      isolated_globals:
        current.isolated_globals === true &&
        typeof globalThis.__weregopherG2IsolatedWorld === "undefined",
      prototype_isolation:
        current.prototype_isolation === true,
      frozen_projection:
        !bridgeFailed &&
        completed.exposureCount > 0 &&
        completed.exposureCount === projections.length &&
        projections.every((projection) => deeplyFrozen(projection)),
      function_round_trip:
        current.value === "isolated:from-page",
      navigation_invalidation: navigationInvalidation,
    };
  };

  const submit = (checks) => {
    window.chrome.webview.postMessage({
      kind: "g2_exact_preload_observation",
      observation_nonce: observationNonce,
      generation,
      checks,
    });
  };

  Object.defineProperty(window, "__weregopherG2PreloadProbe", {
    value: Object.freeze({ generation, observe, submit }),
    writable: false,
    configurable: false,
    enumerable: false,
  });
  post({ kind: "main_ready" });
})();
