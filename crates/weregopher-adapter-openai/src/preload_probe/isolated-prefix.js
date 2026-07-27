(() => {
  "use strict";
  if (window !== window.top) return;

  const channel = "__weregopher_g2_exact_preload_v1";
  const maxDepth = 16;
  const maxNodes = 4096;
  const maxFunctions = 1024;
  const maxExposures = 32;
  const maxStringBytes = 256 * 1024;
  const maxMessageBytes = 1024 * 1024;
  const documentStartedWhileLoading =
    document.readyState === "loading";
  const filename = __WEREGOPHER_PRELOAD_FILENAME__;
  const dirname = __WEREGOPHER_PRELOAD_DIRECTORY__;
  const postMessage = window.postMessage.bind(window);
  const handleNonce = Array.from(
    crypto.getRandomValues(new Uint32Array(4)),
    (value) => value.toString(16).padStart(8, "0"),
  ).join("");
  const functions = new Map();
  const exposures = [];
  let nextFunction = 1;
  let mainReady = false;
  let generation = 0;
  let executionCompleted = false;
  let bridgeFailed = false;

  Object.defineProperty(
    globalThis,
    "__weregopherG2IsolatedWorld",
    {
      value: Object.freeze({ ready: true }),
      writable: false,
      configurable: false,
      enumerable: false,
    },
  );

  const makeHandle = () => {
    if (functions.size >= maxFunctions) {
      throw new TypeError("bridge function limit exceeded");
    }
    const handle = `function-${handleNonce}-${nextFunction++}`;
    return handle;
  };

  const registerFunction = (value) => {
    const handle = makeHandle();
    functions.set(handle, value);
    return handle;
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

  const encode = (value, depth, budget, seen) => {
    if (depth > maxDepth) {
      throw new TypeError("bridge value exceeds its depth limit");
    }
    budget.nodes += 1;
    if (budget.nodes > maxNodes) {
      throw new TypeError("bridge value exceeds its node limit");
    }
    if (value === null) return { kind: "null" };
    if (value === undefined) return { kind: "undefined" };
    if (typeof value === "boolean") {
      return { kind: "boolean", value };
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return { kind: "number", value };
    }
    if (typeof value === "string" && value.length <= maxStringBytes) {
      return { kind: "string", value };
    }
    if (typeof value === "function") {
      return { kind: "function", handle: registerFunction(value) };
    }
    if (value === ipcRenderer) {
      throw new TypeError("raw ipcRenderer projection is unsupported");
    }
    if (typeof value !== "object" || seen.has(value)) {
      throw new TypeError("unsupported bridge value");
    }
    seen.add(value);
    try {
      if (Array.isArray(value)) {
        return {
          kind: "array",
          values: value.map((entry) =>
            encode(entry, depth + 1, budget, seen)
          ),
        };
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("unsupported bridge prototype");
      }
      const entries = [];
      for (const key of Object.keys(value)) {
        rejectDangerousKey(key);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (
          descriptor === undefined ||
          descriptor.get !== undefined ||
          descriptor.set !== undefined
        ) {
          throw new TypeError("unsupported bridge property");
        }
        entries.push([
          key,
          encode(descriptor.value, depth + 1, budget, seen),
        ]);
      }
      return { kind: "object", entries };
    } finally {
      seen.delete(value);
    }
  };

  const post = (payload) => {
    const message = JSON.stringify({
      channel,
      ...(generation > 0 ? { generation } : {}),
      ...payload,
    });
    if (message.length > maxMessageBytes) {
      throw new TypeError("bridge message exceeds its byte limit");
    }
    postMessage(message, "*");
  };

  const exposeInMainWorld = (key, api) => {
    try {
      if (
        typeof key !== "string" ||
        key.length === 0 ||
        key.length > 256 ||
        key.startsWith("__weregopher") ||
        exposures.length >= maxExposures ||
        exposures.some((exposure) => exposure.key === key)
      ) {
        throw new TypeError("invalid bridge projection key");
      }
      rejectDangerousKey(key);
      const descriptor = encode(api, 0, { nodes: 0 }, new Set());
      const serialized = JSON.stringify(descriptor);
      if (serialized.length > maxMessageBytes) {
        throw new TypeError("bridge projection exceeds its byte limit");
      }
      const exposure = { kind: "exposure", key, descriptor };
      exposures.push(exposure);
      if (mainReady) post(exposure);
    } catch {
      bridgeFailed = true;
      throw new TypeError("contextBridge projection was rejected");
    }
  };

  const contextBridge = Object.freeze({ exposeInMainWorld });
  const listeners = new Map();
  const ipcRenderer = {};
  const addListener = (channelName, listener) => {
    if (
      typeof channelName !== "string" ||
      channelName.length === 0 ||
      typeof listener !== "function"
    ) {
      throw new TypeError("invalid ipcRenderer listener");
    }
    const channelListeners = listeners.get(channelName) || new Set();
    channelListeners.add(listener);
    listeners.set(channelName, channelListeners);
    return ipcRenderer;
  };
  const removeListener = (channelName, listener) => {
    listeners.get(channelName)?.delete(listener);
    return ipcRenderer;
  };
  Object.defineProperties(ipcRenderer, {
    on: { value: addListener, enumerable: true },
    addListener: { value: addListener, enumerable: true },
    once: { value: addListener, enumerable: true },
    off: { value: removeListener, enumerable: true },
    removeListener: { value: removeListener, enumerable: true },
    removeAllListeners: {
      value: (channelName) => {
        if (channelName === undefined) listeners.clear();
        else listeners.delete(channelName);
        return ipcRenderer;
      },
      enumerable: true,
    },
    send: { value: () => undefined, enumerable: true },
    sendSync: { value: () => undefined, enumerable: true },
    invoke: {
      value: () => Promise.resolve(undefined),
      enumerable: true,
    },
    postMessage: { value: () => undefined, enumerable: true },
    sendToHost: { value: () => undefined, enumerable: true },
  });
  Object.freeze(ipcRenderer);

  class EventEmitter {
    constructor() {
      this.listeners = new Map();
    }
    on(name, listener) {
      const values = this.listeners.get(name) || new Set();
      values.add(listener);
      this.listeners.set(name, values);
      return this;
    }
    addListener(name, listener) {
      return this.on(name, listener);
    }
    once(name, listener) {
      return this.on(name, listener);
    }
    off(name, listener) {
      this.listeners.get(name)?.delete(listener);
      return this;
    }
    removeListener(name, listener) {
      return this.off(name, listener);
    }
    removeAllListeners(name) {
      if (name === undefined) this.listeners.clear();
      else this.listeners.delete(name);
      return this;
    }
    emit(name, ...args) {
      for (const listener of this.listeners.get(name) || []) {
        listener(...args);
      }
      return this.listeners.has(name);
    }
  }

  const electron = Object.freeze({
    contextBridge,
    ipcRenderer,
    crashReporter: Object.freeze({}),
    nativeImage: Object.freeze({}),
    webFrame: Object.freeze({}),
    webUtils: Object.freeze({}),
  });
  const timerModule = Object.freeze({
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    setImmediate: (callback, ...args) =>
      setTimeout(callback, 0, ...args),
    clearImmediate: clearTimeout,
  });
  const urlModule = Object.freeze({ URL, URLSearchParams });
  const eventsModule = Object.freeze({ EventEmitter });
  const require = (specifier) => {
    switch (specifier) {
      case "electron":
      case "electron/renderer":
        return electron;
      case "events":
      case "node:events":
        return eventsModule;
      case "timers":
      case "node:timers":
        return timerModule;
      case "url":
      case "node:url":
        return urlModule;
      default:
        throw new TypeError("unsupported preload module");
    }
  };
  const process = Object.freeze({
    contextIsolated: true,
    sandboxed: true,
    isMainFrame: true,
    platform: "win32",
    type: "renderer",
    env: Object.freeze({}),
    versions: Object.freeze({}),
  });
  const Buffer = undefined;
  const global = globalThis;
  const setImmediate = timerModule.setImmediate;
  const clearImmediate = timerModule.clearImmediate;

  const cloneCallValue = (value, depth = 0, budget = { nodes: 0 }) => {
    if (depth > maxDepth || ++budget.nodes > maxNodes) {
      throw new TypeError("bridge call value exceeds its limit");
    }
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "boolean"
    ) {
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((entry) =>
        cloneCallValue(entry, depth + 1, budget)
      );
    }
    if (
      typeof value === "object" &&
      (Object.getPrototypeOf(value) === Object.prototype ||
        Object.getPrototypeOf(value) === null)
    ) {
      const result = {};
      for (const key of Object.keys(value)) {
        rejectDangerousKey(key);
        result[key] = cloneCallValue(
          value[key],
          depth + 1,
          budget,
        );
      }
      return result;
    }
    throw new TypeError("unsupported bridge call value");
  };

  const harnessHandle = registerFunction((value) => ({
    value: `isolated:${String(value)}`,
    isolated_globals:
      typeof globalThis.__weregopherG2PageWorld === "undefined",
    prototype_isolation:
      typeof Object.prototype.pollutedByPage === "undefined",
  }));

  window.addEventListener("message", (event) => {
    if (
      event.source !== window ||
      typeof event.data !== "string" ||
      event.data.length > maxMessageBytes
    ) return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.channel !== channel) return;
    if (
      message.kind === "main_ready" &&
      Number.isSafeInteger(message.generation) &&
      message.generation > 0
    ) {
      if (generation !== 0 && generation !== message.generation) return;
      generation = message.generation;
      if (!mainReady) {
        mainReady = true;
        for (const exposure of exposures) post(exposure);
        post({
          kind: "complete",
          document_start: documentStartedWhileLoading,
          exact_source_executed:
            executionCompleted &&
            exposures.length > 0 &&
            !bridgeFailed,
          exposure_count: exposures.length,
          harness_handle: harnessHandle,
        });
      }
      return;
    }
    if (
      message.kind !== "call" ||
      message.generation !== generation ||
      !Number.isSafeInteger(message.id) ||
      typeof message.handle !== "string" ||
      !Array.isArray(message.args)
    ) {
      return;
    }
    const callback = functions.get(message.handle);
    if (callback === undefined) {
      post({
        kind: "call_result",
        id: message.id,
        ok: false,
        code: "stale_handle",
      });
      return;
    }
    Promise.resolve()
      .then(() => callback(...message.args))
      .then(
        (value) =>
          post({
            kind: "call_result",
            id: message.id,
            ok: true,
            value: cloneCallValue(value),
          }),
        () =>
          post({
            kind: "call_result",
            id: message.id,
            ok: false,
            code: "call_failed",
          }),
      );
  });

  try {
    const module = { exports: {} };
    (function (
      require,
      module,
      exports,
      __filename,
      __dirname,
      process,
      Buffer,
      global,
      setImmediate,
      clearImmediate
    ) {
/*__WEREGOPHER_EXACT_PRELOAD_SOURCE_START__*/
