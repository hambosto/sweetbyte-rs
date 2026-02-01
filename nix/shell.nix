{
  mkShell,
  stdenvAdapters,
  sweetbyte-rs,
  clangStdenv,
}:
mkShell.override
  {
    stdenv = stdenvAdapters.useMoldLinker clangStdenv;
  }
  {
    inputsFrom = [
      sweetbyte-rs
    ];
  }
