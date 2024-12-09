const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SymmetricState = @import("symmetric_state.zig").SymmetricState;

const DH = @import("dh.zig").DH;

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

const MessagePattern = []const MessageToken;

const HandshakePattern = struct {
    pre_message_pattern_initiator: ?PreMessagePattern,
    pre_message_pattern_responder: ?PreMessagePattern,
    message_patterns: []MessagePattern,
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

        message_patterns: ArrayList(MessagePattern),

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
            try sym.mixHash(prologue);
            // The initiator's public key(s) are always hashed first.
            if (handshake_pattern.pre_message_pattern_initiator) |i| try sym.mixHash(@tagName(i));
            if (handshake_pattern.pre_message_pattern_responder) |r| try sym.mixHash(@tagName(r));

            return .{
                .message_patterns = ArrayList(MessagePattern).fromOwnedSlice(allocator, handshake_pattern.message_patterns),
                .allocator = allocator,
                .symmetric_state = sym,
                .s = s,
                .e = e,
                .rs = rs,
                .re = re,
                .is_initiator = is_initiator,
            };
        }

        fn writeMessage(self: *Self, payload: []const u8, message: *ArrayList(u8)) !?struct { CipherState(C), CipherState(C) } {
            if (self.message_patterns.items.len == 0) {
                return try self.symmetric_state.split();
            }

            const message_pattern = self.message_patterns.pop();
            for (message_pattern) |token| {
                switch (token) {
                    .e => {
                        const keypair = try dh.generateKeypair(null);
                        self.e = keypair;
                        const pubkey = keypair.inner.public_key;
                        try message.appendSlice(&pubkey);
                        try self.symmetric_state.mixHash(&pubkey);
                    },
                    .s => {
                        const h = try self.symmetric_state.encryptAndHash(&self.s.?.inner.public_key);
                        try message.appendSlice(h);
                    },
                    .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                    .es => {
                        var keypair, const ikm = if (self.is_initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .se => {
                        var keypair, const ikm = if (self.is_initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                    .psk => {
                        // no-op
                    },
                }
            }

            const h = try self.symmetric_state.encryptAndHash(payload);
            try message.appendSlice(h);

            return null;
        }

        fn readMessage(self: *Self, message: []const u8, payload_buf: *ArrayList(u8)) !?struct { CipherState(C), CipherState(C) } {
            if (self.message_patterns.items.len == 0) {
                return try self.symmetric_state.split();
            }

            const message_pattern = self.message_patterns.pop();
            var msg_idx: usize = 0;
            for (message_pattern) |token| {
                switch (token) {
                    .e => {
                        std.debug.assert(self.re == null);
                        self.re = undefined;
                        std.debug.print("msg idx = {any}\n", .{msg_idx});
                        @memcpy(&self.re.?, message[msg_idx .. msg_idx + dh.KeyPair.DHLEN]);
                        msg_idx += dh.KeyPair.DHLEN;
                        try self.symmetric_state.mixHash(&self.re.?);
                    },
                    .s => {
                        const len: usize = if (self.symmetric_state.cipher_state.hasKey()) dh.KeyPair.DHLEN + 16 else dh.KeyPair.DHLEN;
                        const temp = if (self.symmetric_state.cipher_state.hasKey()) message[msg_idx .. msg_idx + len] else message[msg_idx .. msg_idx + len];

                        msg_idx += len;
                        @memcpy(&self.rs.?, try self.symmetric_state.decryptAndHash(temp));
                    },
                    .ee => try self.symmetric_state.mixKey(self.allocator, &self.re.?),
                    .es => {
                        var keypair, const ikm = if (self.is_initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                        try self.symmetric_state.mixKey(self.allocator, &try keypair.?.DH(ikm.?));
                    },
                    .se => {
                        var keypair, const ikm = if (self.is_initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        try self.symmetric_state.mixKey(self.allocator, &try keypair.?.DH(ikm.?));
                    },
                    .ss => try self.symmetric_state.mixKey(self.allocator, &try self.s.?.DH(self.rs.?)),
                    .psk => {
                        // no-op
                    },
                }
            }
            const h = try self.symmetric_state.decryptAndHash(message[msg_idx..]);
            try payload_buf.appendSlice(h);

            return null;
        }

        pub fn deinit(self: *Self) void {
            if (self.message_patterns.items.len != 0) {
                self.message_patterns.deinit();
            }
        }
    };
}

test "writeMessage - simple" {
    const hs_state = HandshakeState(Blake2s256, ChaCha20Poly1305);

    var seed = [_]u8{1} ** 32;
    const alice_static = try hs_state.dh.generateKeypair(seed);
    seed = [_]u8{2} ** 32;
    const bob_static = try hs_state.dh.generateKeypair(seed);

    var msg_patterns = [_]MessagePattern{&[_]MessageToken{.e}};

    var alice_handshake = try hs_state.init(
        std.testing.allocator,
        .X,
        .{
            .pre_message_pattern_initiator = null,
            .pre_message_pattern_responder = null,
            .message_patterns = &msg_patterns,
        },
        true,
        "",
        alice_static,
        null,
        bob_static.inner.public_key,
        null,
    );
    defer alice_handshake.deinit();

    var buf = ArrayList(u8).init(std.testing.allocator);
    try buf.appendSlice("hello ");
    defer buf.deinit();
    _ = try alice_handshake.writeMessage("world!", &buf);
}

test "empty patterns" {
    const C = ChaCha20Poly1305;
    const hs_state = HandshakeState(Blake2s256, C);

    var seed = [_]u8{1} ** 32;
    const alice_static = try hs_state.dh.generateKeypair(seed);
    seed = [_]u8{2} ** 32;
    const bob_static = try hs_state.dh.generateKeypair(seed);

    var msg_patterns = [_]MessagePattern{};

    var alice_handshake = try hs_state.init(
        std.testing.allocator,
        .X,
        .{
            .pre_message_pattern_initiator = null,
            .pre_message_pattern_responder = null,
            .message_patterns = &msg_patterns,
        },
        true,
        "",
        alice_static,
        null,
        bob_static.inner.public_key,
        null,
    );
    var buf = ArrayList(u8).init(std.testing.allocator);
    try buf.appendSlice("hello ");
    defer buf.deinit();
    const out = try alice_handshake.writeMessage("world!", &buf);
    try std.testing.expect(@TypeOf(out.?[0]) == CipherState(C));
    try std.testing.expect(@TypeOf(out.?[1]) == CipherState(C));
}
