//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");

const X25519 = std.crypto.dh.X25519;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

const CipherState = @import("./cipher.zig").CipherState;
const SymmetricState = @import("./symmetric_state.zig").SymmetricState;

/// A Noise Diffie-Hellman function.
///
/// Only Curve25519 is supported, since zig stdlib does not have Curve448 support.
pub fn DH() type {
    const DHLEN = 32;

    const Self = @This();

    return struct {
        pub const KeyPair = X25519.KeyPair;

        /// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements.
        /// A public_key represents an encoding of a DH public key into a byte sequence of length `DHLEN`.
        /// The public_key encoding details are specific to each set of DH functions.
        ///
        /// Returns the `Keypair`.
        fn generateKeypair(seed: ?[32]u8) KeyPair {
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
    _ = @import("hash.zig");
    _ = @import("handshake_state.zig");
    _ = @import("symmetric_state.zig");
}
