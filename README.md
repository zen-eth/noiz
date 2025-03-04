# noize

A **work-in-progress** [Noise Protocol Framework](https://noiseprotocol.org/) in Zig.

_WARNING: This library has not been audited_

## Crypto

All cryptographic primitives listed in the [official specification (rev34)](https://github.com/noiseprotocol/noise_spec/blob/rev34/noise.md) are supported aside from Curve448, because zig stdlib does not have it, and [does not plan to prioritize its inclusion due to various reasons](https://github.com/ziglang/zig/issues/22101#issuecomment-2507982794).

[Other crypto algorithms](https://github.com/noiseprotocol/noise_wiki/wiki/Unofficial-crypto-algorithms-list) are not supported at this time.

## Test

Noize is built in zig 0.14.0:

To test:

```sh
zig build test
```

To test the test vectors only:

```sh
zig build test -Dfilter="cacophony"
```
