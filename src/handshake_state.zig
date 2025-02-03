const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const builtin = @import("builtin");

const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const HandshakePatternName = @import("handshake_pattern.zig").HandshakePatternName;
const HandshakePattern = @import("handshake_pattern.zig").HandshakePattern;
const patternFromName = @import("handshake_pattern.zig").patternFromName;
const MessagePattern = @import("handshake_pattern.zig").MessagePattern;

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
const Cipher = @import("./cipher.zig").Cipher;
const Hash = @import("hash.zig").Hash;

//Noise provides a pre-shared symmetric key or PSK mode to support protocols where both parties have a 32-byte shared secret key.
const PSK_SIZE = 32;

pub fn keypairFromSecretKey(secret_key: []const u8) !DH.KeyPair {
    var sk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sk, secret_key);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    return DH.KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
        .public_key = pk,
        .secret_key = sk,
    } };
}
///The max message length in bytes.
///
///See: http://www.noiseprotocol.org/noise.html#message-format
pub const MAX_MESSAGE_LEN = 65535;

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

pub const HandshakeState = struct {
    const Self = @This();

    allocator: Allocator,
    /// The local static key pair
    s: ?DH.KeyPair = null,

    /// The local ephemeral key pair
    e: ?DH.KeyPair = null,

    /// rs: The remote party's static public key
    rs: ?[DH.KeyPair.public_length]u8 = null,

    /// re: The remote party's ephemeral public key
    re: ?[DH.KeyPair.public_length]u8 = null,

    psks: ?[]const u8 = null,

    /// A party can either be the initiator or the responder.
    /// This is true if `Self` is the intiator.
    is_initiator: bool,

    message_patterns: ArrayList(MessagePattern),

    pattern_idx: usize = 0,
    psk_idx: usize = 0,

    symmetric_state: SymmetricState,

    /// A handshake pattern name section contains a handshake pattern name plus a sequence of zero or more pattern modifiers.
    pub const HandshakePatternNameSection: []const u8 = [_][]const u8{};

    const Keys = struct {
        /// The local static key pair
        s: ?DH.KeyPair = null,

        /// The local ephemeral key pair
        e: ?DH.KeyPair = null,

        /// rs: The remote party's static public key
        rs: ?[DH.KeyPair.public_length]u8 = null,

        /// re: The remote party's ephemeral public key
        re: ?[DH.KeyPair.public_length]u8 = [_]u8{0} ** 32,
    };

    /// Initialize(handshake_pattern, initiator, prologue, s, e, rs, re):
    pub fn init(
        protocol_name: []const u8,
        allocator: Allocator,
        handshake_pattern: HandshakePattern,
        is_initiator: bool,
        prologue: []const u8,
        psks: ?[]const u8,
        keys: Keys,
    ) !Self {
        var sym = try SymmetricState.init(allocator, protocol_name);
        try sym.mixHash(prologue);

        if (is_initiator) {
            // The initiator's public key(s) are always hashed first.
            if (handshake_pattern.pre_message_pattern_initiator) |i| {
                const key_s = keys.s.?.inner.public_key[0..];
                const key_e = keys.e.?.inner.public_key[0..];

                switch (i) {
                    .s => try sym.mixHash(key_s),
                    .e => {
                        try sym.mixHash(key_e);
                    },
                    else => @panic(""),
                }
            }
            if (handshake_pattern.pre_message_pattern_responder) |r| {
                const key_rs = keys.rs.?[0..];
                switch (r) {
                    .s => try sym.mixHash(key_rs),
                    .e => {
                        if (keys.re) |re| {
                            try sym.mixHash(&re);
                        }
                    },
                    else => @panic(""),
                }
            }
        } else {
            // The initiator's public key(s) are always hashed first.
            if (handshake_pattern.pre_message_pattern_initiator) |i| {
                const key_rs = if (keys.rs) |rs| rs[0..] else null;
                const key_re = if (keys.re) |re| re[0..] else null;
                switch (i) {
                    .s => if (key_rs) |rs| try sym.mixHash(rs),
                    .e => {
                        if (key_re) |re| {
                            try sym.mixHash(re);
                        }
                    },
                    else => @panic(""),
                }
            }
            if (handshake_pattern.pre_message_pattern_responder) |r| {
                const key_s = keys.s.?.inner.public_key[0..];
                const key_e = keys.e.?.inner.public_key[0..];

                switch (r) {
                    .s => try sym.mixHash(key_s),
                    .e => {
                        try sym.mixHash(key_e);
                    },
                    else => @panic(""),
                }
            }
        }

        return .{
            .allocator = allocator,
            .message_patterns = handshake_pattern.message_patterns,
            .symmetric_state = sym,
            .s = keys.s,
            .e = keys.e,
            .rs = keys.rs,
            .re = keys.re,
            .is_initiator = is_initiator,
            .psks = psks,
        };
    }

    pub fn writeMessage(self: *Self, payload: []const u8, message: *ArrayList(u8)) !?struct { CipherState, CipherState } {
        const pattern = self.message_patterns.items[self.pattern_idx];
        for (pattern) |token| {
            switch (token) {
                .e => {
                    if (!builtin.is_test) {
                        const keypair = try DH.KeyPair.generate(null);
                        self.e = keypair;
                    }
                    const pubkey = self.e.?.inner.public_key;
                    try message.appendSlice(&pubkey);
                    try self.symmetric_state.mixHash(&pubkey);

                    if (self.psks) |_| try self.symmetric_state.mixKey(&pubkey);
                },
                .s => {
                    var ciphertext: [48]u8 = undefined;
                    const h = try self.symmetric_state.encryptAndHash(&ciphertext, &self.s.?.inner.public_key);
                    try message.appendSlice(h);
                },
                .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                .es => {
                    var keypair, const ikm = if (self.is_initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                    const dh_out = try keypair.?.DH(ikm.?);
                    try self.symmetric_state.mixKey(&dh_out);
                },
                .se => {
                    var keypair, const ikm = if (self.is_initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                    const dh_out = try keypair.?.DH(ikm.?);
                    try self.symmetric_state.mixKey(&dh_out);
                },
                .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                .psk => {
                    // no-op
                    try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                    self.psk_idx += 1;
                },
            }
        }

        var ciphertext: [100]u8 = undefined;
        const h = try self.symmetric_state.encryptAndHash(&ciphertext, payload);
        try message.appendSlice(ciphertext[0..h.len]);
        self.pattern_idx += 1;
        if (self.pattern_idx == self.message_patterns.items.len) return try self.symmetric_state.split();

        return null;
    }

    pub fn readMessage(self: *Self, message: []const u8, payload_buf: *ArrayList(u8)) !?struct { CipherState, CipherState } {
        var msg_idx: usize = 0;
        const pattern = self.message_patterns.items[self.pattern_idx];
        for (pattern) |token| {
            switch (token) {
                .e => {
                    if (!builtin.is_test) {
                        std.debug.assert(self.re == null);
                        self.re = undefined;
                    }
                    @memcpy(self.re.?[0..], message[msg_idx .. msg_idx + DH.KeyPair.DHLEN]);
                    try self.symmetric_state.mixHash(&self.re.?);

                    if (self.psks) |_| try self.symmetric_state.mixKey(&self.re.?);
                    msg_idx += DH.KeyPair.DHLEN;
                },
                .s => {
                    const len: usize = if (self.symmetric_state.cipher_state.hasKey()) DH.KeyPair.DHLEN + 16 else DH.KeyPair.DHLEN;
                    const temp = if (self.symmetric_state.cipher_state.hasKey()) message[msg_idx .. msg_idx + len] else message[msg_idx .. msg_idx + len];

                    msg_idx += len;
                    _ = try self.symmetric_state.decryptAndHash(self.rs.?[0..], temp);
                },
                .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                .es => {
                    var keypair = if (self.is_initiator) self.e else self.s;
                    const ikm = if (self.is_initiator) self.rs else self.re;
                    try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                },
                .se => {
                    var keypair, const ikm = if (self.is_initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                    try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                },
                .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                .psk => {
                    // no-op
                    //
                    try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                    self.psk_idx += 1;
                },
            }
        }

        var plaintext: [MAX_MESSAGE_LEN]u8 = undefined;
        const h = try self.symmetric_state.decryptAndHash(plaintext[0 .. message.len - msg_idx], message[msg_idx..message.len]);
        try payload_buf.appendSlice(h);
        self.pattern_idx += 1;
        if (self.pattern_idx == self.message_patterns.items.len) return try self.symmetric_state.split();

        return null;
    }

    pub fn deinit(self: *Self) void {
        self.message_patterns.deinit();
        self.symmetric_state.deinit();
        if (self.psks) |psks| {
            self.allocator.free(psks);
        }
    }
};
