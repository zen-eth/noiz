const std = @import("std");
const SymmetricState = @import("symmetric_state.zig").SymmetricState;

const DH = @import("root.zig").DH;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

const NOISE_ = "Noise_";
const DH_Functions = [][]const u8{"25519"};
const Cipher_Functions = [][]const u8{ "Aes256Gcm", "ChaCha20Poly1305" };
const Hash_Functions = [][]const u8{ "Sha256", "Sha512", "Blake2s256", "Blake2b512" };

pub fn noiseProtocolName() []const u8 {
    return "Noise_";
}

const Pattern = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
};

pub fn HandshakeState(comptime H: type, comptime C: type) type {
    const Self = @This();
    return struct {
        symmetric_state: SymmetricState(H, C),

        /// The local static key pair
        s: dh.KeyPair,

        /// The local ephemeral key pair
        e: dh.KeyPair,
        /// rs: The remote party's static public key
        rs: []u8,

        /// re: The remote party's ephemeral public key
        re: []u8,

        /// A party can either be the initiator or the responder.
        /// This is true if `Self` is the intiator.
        initiator: bool,

        message_patterns: [][]const Pattern,

        const dh = DH();

        /// Initialize(handshake_pattern, initiator, prologue, s, e, rs, re):
        pub fn init(
            handshake_pattern: anytype,
            initiator: bool,
            prologue: []const u8,
            s: ?dh.KeyPair,
            e: ?dh.KeyPair,
            rs: ?[]const u8,
            re: ?[]const u8,
        ) Self {
            _ = prologue;
            return .{
                .s = s,
                .e = e,
                .rs = rs,
                .re = re,
                .initiator = initiator,
                .message_patterns = handshake_pattern,
            };
        }
    };
}

test "handshake" {
    const hs_state = HandshakeState(Sha256, ChaCha20Poly1305);
    std.debug.print("hs = {any}", .{hs_state});
}
