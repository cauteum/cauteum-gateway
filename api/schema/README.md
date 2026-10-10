# Control API compatibility baseline

`control-5e20fa2f6943.binpb` is the Buf image built from
`api/proto` at Gateway commit
`5e20fa2f6943da8cb41a9df722d436d6d1ac0cce`, the last committed Control API
before the current release work. SHA-256:
`3b2caa8753450ee0a1b2c6114cadf8a645f146b7f0ea2572f52064e6f89ae5f9`.

CI always runs `buf breaking` against this immutable image. Replace the
baseline only as an explicit versioned contract release; keep older images for
supported release lines.
