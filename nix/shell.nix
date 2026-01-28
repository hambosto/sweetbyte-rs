{
  mkShell,
  stdenvAdapters,
  cargo-watch,
  sweetbyte-rs,
}:
mkShell.override
  (old: {
    stdenv = stdenvAdapters.useMoldLinker old.stdenv;
  })
  {
    inputsFrom = [
      sweetbyte-rs
    ];

    packages = [
      cargo-watch
    ];
  }
