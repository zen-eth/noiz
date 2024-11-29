//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");

const X25519 = std.crypto.dh.X25519;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

/// Instantiates a Noise hash function.
///
/// Only these hash functions are supported in accordance with the spec: `Sha256`, `Sha512`, `Blake2s256`, `Blake2b512`.
///
/// https://noiseprotocol.org/noise.html#hash-functions
// TODO: implement hmac-hash and hkdf
fn Hash(comptime H: type) !type {
    const _Hash = H;

    const HASHLEN = comptime switch (H) {
        Sha256, Blake2s256 => 32,
        Sha512, Blake2b512 => 64,
        else => return error.UnsupportedHash,
    };

    const BLOCKLEN = comptime switch (H) {
        Sha256, Blake2s256 => 64,
        Sha512, Blake2b512 => 128,
        else => return error.UnsupportedHash,
    };

    return struct {
        /// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function.
        ///
        /// Returns an output of `HASHLEN` bytes.
        fn hash(input: []const u8, options: anytype) [HASHLEN]u8 {
            _ = BLOCKLEN;
            var out: [HASHLEN]u8 = undefined;
            _Hash.hash(input, &out, options);
            return out;
        }
    };
}

/// A Noise Diffie-Hellman function.
///
/// Only Curve25519 is supported, since zig stdlib does not have Curve448 support.
fn DH() type {
    const DHLEN = 32;

    const Keypair = X25519.Keypair;

    const Self = @This();

    return struct {
        /// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements.
        /// A public_key represents an encoding of a DH public key into a byte sequence of length `DHLEN`.
        /// The public_key encoding details are specific to each set of DH functions.
        ///
        /// Returns the `Keypair`.
        fn generateKeypair(seed: ?[32]u8) Keypair {
            return X25519.KeyPair.create(seed);
        }

        /// Performs a Diffie-Hellman calculation between the private key in `Keypair` and the `public_key`.
        ///
        /// Returns an output sequence of bytes of length `DHLEN`.
        fn DH(self: *Self, public_key: [X25519.public_length]u8) [DHLEN]u8 {
            const shared_secret = try X25519.scalarmult(self.secret_key, public_key);
            return shared_secret;
        }
    };
}

test {
    _ = @import("cipher.zig");
}
