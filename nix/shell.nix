{
  mkShell,
  stdenvAdapters,
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
  }
