"use strict";

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const result = await window.weregopher.invoke("echo", [
      { kind: "string", value: "from-renderer" },
    ]);
    document.body.dataset.result = result.value;
    window.chrome.webview.postMessage({
      kind: "fixture_observation",
      value: result.value,
      origin: window.location.origin,
    });
  } catch (error) {
    window.chrome.webview.postMessage({
      kind: "fixture_failure",
      message: String(error),
    });
  }
});
