
/*__WEREGOPHER_EXACT_PRELOAD_SOURCE_END__*/
    }).call(
      module.exports,
      require,
      module,
      module.exports,
      filename,
      dirname,
      process,
      Buffer,
      global,
      setImmediate,
      clearImmediate,
    );
    executionCompleted = true;
  } catch {
    executionCompleted = false;
  }
  post({ kind: "isolated_ready" });
})();
