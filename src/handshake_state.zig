const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

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

const CipherState = @import("./cipher.zig").CipherState;
const Hash = @import("hash.zig").Hash;

pub fn noiseProtocolName() []const u8 {
    return "Noise_";
}

const MessageToken = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
};

const PreMessagePattern = enum {
    e,
    s,
    es,
    empty,
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
const HandshakePatternName = enum {
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

const MessagePattern = []MessageToken;

const HandshakePattern = struct {
    pre_message_pattern_initiator: ?PreMessagePattern,
    pre_message_pattern_responder: ?PreMessagePattern,
    message_pattern: []MessagePattern,
};

fn deriveProtocolName(
    comptime H: type,
    comptime C: type,
    allocator: Allocator,
    handshake_pattern_name: HandshakePatternName,
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
    const protocol_name = try std.fmt.allocPrint(allocator, "Noise_{s}_{s}", .{ @tagName(handshake_pattern_name), suffix });
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
    return struct {
        const Self = @This();

        const dh = DH();

        allocator: Allocator,
        /// The local static key pair
        s: ?dh.KeyPair,

        /// The local ephemeral key pair
        e: ?dh.KeyPair,

        /// rs: The remote party's static public key
        rs: ?[dh.KeyPair.public_length]u8,

        /// re: The remote party's ephemeral public key
        re: ?[dh.KeyPair.public_length]u8,

        /// A party can either be the initiator or the responder.
        /// This is true if `Self` is the intiator.
        is_initiator: bool,

        message_patterns: []const MessageToken = &[_]MessageToken{.e},

        symmetric_state: SymmetricState(H, C),

        /// A handshake pattern name section contains a handshake pattern name plus a sequence of zero or more pattern modifiers.
        pub const HandshakePatternNameSection: []const u8 = [_][]const u8{};

        /// Initialize(handshake_pattern, initiator, prologue, s, e, rs, re):
        pub fn init(
            allocator: Allocator,
            // TODO: fix
            handshake_pattern_name: HandshakePatternName,
            handshake_pattern: HandshakePattern,
            is_initiator: bool,
            prologue: []const u8,
            s: ?dh.KeyPair,
            e: ?dh.KeyPair,
            rs: ?[dh.KeyPair.public_length]u8,
            re: ?[dh.KeyPair.public_length]u8,
        ) !Self {
            const protocol_name = try deriveProtocolName(H, C, allocator, handshake_pattern_name);
            defer allocator.free(protocol_name);
            var sym = try SymmetricState(H, C).init(allocator, protocol_name);
            try sym.mixHash(allocator, prologue);
            // TODO: Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and responder have pre-messages, the initiator's public keys are hashed first. If multiple public keys are listed in either party's pre-message, the public keys are hashed in the order that they are listed.

            // TODO: Sets message_patterns to the message patterns from handshake_pattern.
            //
            // pre message: e // s // e, s // empty

            if (handshake_pattern.pre_message_pattern_initiator) |i| {
                try sym.mixHash(allocator, @tagName(i));
            }
            if (handshake_pattern.pre_message_pattern_responder) |r| {
                try sym.mixHash(allocator, @tagName(r));
            }

            return .{
                .allocator = allocator,
                .symmetric_state = sym,
                .s = s,
                .e = e,
                .rs = rs,
                .re = re,
                .is_initiator = is_initiator,
            };
        }

        fn writeMessage(self: *Self, payload: []const u8, message: *ArrayList(u8)) !void {
            for (self.message_patterns) |pattern| {
                switch (pattern) {
                    .e => {
                        const keypair = (try dh.generateKeypair(null));
                        self.e = keypair;
                        try message.appendSlice(payload);
                        try self.symmetric_state.mixHash(self.allocator, &self.e.?.inner.public_key);
                    },
                    .s => {
                        // TODO: append encrypt & hash
                    },
                    .ee => try self.symmetric_state.mixKey(self.allocator, &try self.e.?.DH(self.re.?)),
                    .es => {
                        const out = if (self.is_initiator) .{ self.rs, self.e } else .{ self.re, self.s };
                        const ikm = out[0].?;
                        var keypair = out[1].?;
                        try self.symmetric_state.mixKey(self.allocator, &try keypair.DH(ikm));
                    },
                    .se => {},
                    .ss => try self.symmetric_state.mixKey(self.allocator, &try self.e.?.DH(self.rs.?)),
                    .psk => {},
                }
            }
        }

        fn readMessage(message: []const u8, payload_buf: *[]u8) void {
            _ = payload_buf;
            _ = message;
        }
    };
}

test "handshake" {
    var alice_handshake = try HandshakeState(Sha256, ChaCha20Poly1305).init(
        std.testing.allocator,
        .XX,
        .{
            .pre_message_pattern_initiator = null,
            .pre_message_pattern_responder = null,
            .message_pattern = &[_]MessagePattern{},
        },
        false,
        "",
        null,
        null,
        null,
        null,
    );
    var buf = ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try alice_handshake.writeMessage("world", &buf);
    std.debug.print("hs = {any}", .{alice_handshake});
}
