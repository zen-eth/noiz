const std = @import("std");
const Allocator = std.mem.Allocator;
const SymmetricState = @import("symmetric_state.zig").SymmetricState;

const DH = @import("root.zig").DH;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const Sha512 = std.crypto.hash.sha2.Sha512;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

const NOISE_ = "Noise_";
const DH_Functions = [_][]const u8{"25519"};
const Cipher_Functions = [_][]const u8{ "Aes256Gcm", "ChaCha20Poly1305" };
const Hash_Functions = [_][]const u8{ "Sha256", "Sha512", "Blake2s256", "Blake2b512" };

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

/// The following handshake patterns represent interactive protocols. These 12 patterns are called the fundamental interactive handshake patterns.
/// The fundamental interactive patterns are named with two characters, which indicate the status of the initiator and responder's static keys:
///
/// The first character refers to the initiator's static key:
///
///    N = No static key for initiator
///    K = Static key for initiator Known to responder
///    X = Static key for initiator Xmitted ("transmitted") to responder
///    I = Static key for initiator Immediately transmitted to responder, despite reduced or absent identity hiding
///
/// The second character refers to the responder's static key:
///
///    N = No static key for responder
///    K = Static key for responder Known to initiator
///    X = Static key for responder Xmitted ("transmitted") to initiator
const HandshakePattern = enum {
    N,
    K,
    X,
    I,
    NN,
    NK,
    NX,
    KN,
    KK,
    KX,
    XN,
    XK,
    XX,
    IN,
    IK,
    IX,
};

fn deriveProtocolName(
    comptime H: type,
    comptime C: type,
    allocator: Allocator,
    handshake_pattern: HandshakePattern,
) ![]const u8 {
    const cipher = comptime switch (C) {
        Aes256Gcm => "AESGCM",
        ChaCha20Poly1305 => "ChaChaPoly",
        else => @compileError(std.fmt.comptimePrint("Unsupported cipher: {any}", .{C})),
    };

    const hash = comptime switch (H) {
        Sha256 => "SHA256",
        Blake2s256 => "BLAKE2s",
        Sha512 => "SHA512",
        Blake2b512 => "BLAKE2b",
        else => @compileError(std.fmt.comptimePrint("Unsupported hash: {any}", .{H})),
    };

    const suffix = DH_Functions[0] ++ "_" ++ cipher ++ "_" ++ hash;
    const protocol_name = try std.fmt.allocPrint(allocator, "Noise_{s}_{s}", .{ @tagName(handshake_pattern), suffix });
    return protocol_name;
}

test "deriveProtocolName" {
    const allocator = std.testing.allocator;
    // Noise_XX_25519_AESGCM_SHA256
    {
        const protocol_name = try deriveProtocolName(Sha256, Aes256Gcm, allocator, .XX);
        defer allocator.free(protocol_name);
        try std.testing.expectEqualStrings("Noise_XX_25519_AESGCM_SHA256", protocol_name);
    }

    // Noise_N_25519_ChaChaPoly_BLAKE2s
    {
        const protocol_name = try deriveProtocolName(Blake2s256, ChaCha20Poly1305, allocator, .N);
        defer allocator.free(protocol_name);
        try std.testing.expectEqualStrings("Noise_N_25519_ChaChaPoly_BLAKE2s", protocol_name);
    }
}

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

            deriveProtocolName(handshake_pattern, H, C);
            return .{
                .s = s,
                .e = e,
                .rs = rs,
                .re = re,
                .initiator = initiator,
                .message_patterns = handshake_pattern,
            };
        }

        fn writeMessage(payload: []const u8, msg_buf: *[]u8) void {
            _ = payload;
            _ = msg_buf;
        }

        fn readMessage(message: []const u8, payload_buf: *[]u8) void {
            _ = payload_buf;
            _ = message;
        }
    };
}

test "handshake" {
    const hs_state = HandshakeState(Sha256, ChaCha20Poly1305);
    std.debug.print("hs = {any}", .{hs_state});
}
