const std = @import("std");

const X25519 = std.crypto.dh.X25519;

pub const KeyPair = struct {
    const Self = @This();

    inner: X25519.KeyPair,

    pub const DHLEN = 32;
    pub const public_length = X25519.public_length;

    /// Performs a Diffie-Hellman calculation between the private key in `Keypair` and the `public_key`.
    ///
    ///
    /// Returns an output sequence of bytes of length `DHLEN`.
    pub fn DH(self: *Self, public_key: [X25519.public_length]u8) ![DHLEN]u8 {
        const shared_secret = try X25519.scalarmult(self.inner.secret_key, public_key);
        return shared_secret;
    }
};

/// A Noise Diffie-Hellman function.
///
/// Only Curve25519 is supported, since zig stdlib does not have Curve448 support.
pub fn DH() type {
    return struct {
        const Self = @This();

        /// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements.
        /// A public_key represents an encoding of a DH public key into a byte sequence of length `DHLEN`.
        /// The public_key encoding details are specific to each set of DH functions.
        ///
        /// Returns the `Keypair`.
        pub fn generateKeypair(seed: ?[32]u8) !KeyPair {
            return .{
                .inner = if (seed) |s| try X25519.KeyPair.generateDeterministic(s) else X25519.KeyPair.generate(),
            };
        }
    };
}
test "DH" {
    const dh = DH();
    var kp1 = try dh.generateKeypair(null);
    var kp2 = try dh.generateKeypair(null);
    _ = try kp1.DH([_]u8{29} ** 32);
    _ = try kp2.DH([_]u8{29} ** 32);
}
