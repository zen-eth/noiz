//! Contains the implementation for a Noise Diffie-Hellman function.
//!
//! Note that only X25519 is supported in the standard library,
//! because X448 does not provide significant upside and quantum cryptography
//! will break both curves anyway.
//!
//! See: https://github.com/ziglang/zig/issues/22101
const std = @import("std");

const X25519 = std.crypto.dh.X25519;

/// X25519 DH function.
pub const DH = struct {
    /// A X25519 key pair.
    pub const KeyPair = struct {
        const Self = @This();

        inner: X25519.KeyPair,

        pub const DHLEN = 32;
        pub const public_length = X25519.public_length;

        // Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements.
        // A public_key represents an encoding of a DH public key into a byte sequence of length `DHLEN`.
        // The public_key encoding details are specific to each set of DH functions.
        //
        // Returns the `Keypair`.
        pub fn generate(seed: ?[32]u8) !KeyPair {
            return .{
                .inner = if (seed) |s| try X25519.KeyPair.generateDeterministic(s) else X25519.KeyPair.generate(),
            };
        }

        /// Performs a Diffie-Hellman calculation between the private key in `Keypair` and the `public_key`.
        ///
        /// Returns an output sequence of bytes of length `DHLEN`.
        pub fn DH(self: *Self, public_key: [X25519.public_length]u8) ![DHLEN]u8 {
            const shared_secret = try X25519.scalarmult(self.inner.secret_key, public_key);
            return shared_secret;
        }
    };
};
