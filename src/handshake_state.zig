const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const builtin = @import("builtin");

const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const HandshakePatternName = @import("handshake_pattern.zig").HandshakePatternName;
const HandshakePattern = @import("handshake_pattern.zig").HandshakePattern;
const patternFromName = @import("handshake_pattern.zig").patternFromName;
const MessagePatternArray = @import("handshake_pattern.zig").MessagePatternArray;

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

/// A party in a Noise handshake can either be the initiator or the responder.
pub const Role = enum {
    Initiator,
    Responder,
};

/// Represents the handshake state machine maintained by each party during a handshake.
/// This state machine is in charge of sequentially processing tokens from a `MessagePatternArray`
/// for key exchange.
///
/// Contains a `SymmetricState` and `DH` variables (s, e, rs, re) and a `HandshakePattern`.
///
/// After the handshake phase, this should be deleted (except for the hash value `h`).
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
    role: Role,

    message_patterns: MessagePatternArray,

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

    /// Initializes a handshake state machine.
    ///
    /// Deinitialize with `deinit`.
    pub fn init(
        protocol_name: []const u8,
        allocator: Allocator,
        handshake_pattern: HandshakePattern,
        role: Role,
        prologue: []const u8,
        psks: ?[]const u8,
        keys: Keys,
    ) !Self {
        var sym = try SymmetricState.init(allocator, protocol_name);
        try sym.mixHash(allocator, prologue);

        if (role == .Initiator) {
            // The initiator's public key(s) are always hashed first.
            if (handshake_pattern.pre_message_pattern_initiator) |i| {
                const key_s = keys.s.?.inner.public_key[0..];
                const key_e = keys.e.?.inner.public_key[0..];

                switch (i) {
                    .s => try sym.mixHashBounded(key_s),
                    .e => {
                        try sym.mixHashBounded(key_e);
                    },
                    else => @panic(""),
                }
            }
            if (handshake_pattern.pre_message_pattern_responder) |r| {
                const key_rs = keys.rs.?[0..];
                switch (r) {
                    .s => try sym.mixHashBounded(key_rs),
                    .e => {
                        if (keys.re) |re| {
                            try sym.mixHashBounded(&re);
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
                    .s => if (key_rs) |rs| try sym.mixHashBounded(rs),
                    .e => if (key_re) |re| try sym.mixHashBounded(re),
                    else => @panic(""),
                }
            }
            if (handshake_pattern.pre_message_pattern_responder) |r| {
                switch (r) {
                    .s => if (keys.s) |s| try sym.mixHashBounded(s.inner.public_key[0..]),
                    .e => if (keys.e) |e| try sym.mixHashBounded(e.inner.public_key[0..]),
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
            .role = role,
            .psks = psks,
        };
    }

    /// Fetches and deletes the next message pattern from `message_patterns` and processes each token sequentially from the pattern.
    /// Aborts if any `encryptAndHash()` calls returns an error.
    pub fn writeMessage(self: *Self, payload: []const u8, message: *ArrayList(u8)) !?struct { CipherState, CipherState } {
        const pattern = self.message_patterns.next();
        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) {
                            const keypair = try DH.KeyPair.generate(null);
                            self.e = keypair;
                        }
                        const pubkey = self.e.?.inner.public_key;
                        try message.appendSlice(&pubkey);
                        try self.symmetric_state.mixHashBounded(&pubkey);

                        if (self.psks) |psks| {
                            if (psks.len > 0) try self.symmetric_state.mixKey(&pubkey);
                        }
                    },
                    .s => {
                        var ciphertext: [48]u8 = undefined;
                        const h = try self.symmetric_state.encryptAndHash(self.allocator, &ciphertext, &self.s.?.inner.public_key);
                        try message.appendSlice(h);
                    },
                    .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                    .es => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                        const dh_out = try keypair.?.DH(ikm.?);
                        try self.symmetric_state.mixKey(&dh_out);
                    },
                    .se => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        const dh_out = try keypair.?.DH(ikm.?);
                        try self.symmetric_state.mixKey(&dh_out);
                    },
                    .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                    .psk => {
                        // no-op
                        try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                        // self.psk_idx += 1;
                    },
                }
            }
        }

        var ciphertext: [100]u8 = undefined;
        const h = try self.symmetric_state.encryptAndHash(self.allocator, &ciphertext, payload);
        try message.appendSlice(ciphertext[0..h.len]);
        if (self.message_patterns.isFinished()) {
            return try self.symmetric_state.split();
        }

        return null;
    }

    /// Fetches and deletes the next message pattern from `message_patterns` and processes each token sequentially from the pattern.
    ///
    /// Aborts if any `decryptAndHash()` calls returns an error.
    pub fn readMessage(self: *Self, message: []const u8, payload_buf: *ArrayList(u8)) !?struct { CipherState, CipherState } {
        var msg_idx: usize = 0;

        const pattern = self.message_patterns.next();

        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) {
                            std.debug.assert(self.re == null);
                            self.re = undefined;
                        }
                        @memcpy(self.re.?[0..], message[msg_idx .. msg_idx + DH.KeyPair.DHLEN]);
                        try self.symmetric_state.mixHashBounded(&self.re.?);

                        if (self.psks) |psks| {
                            if (psks.len > 0) try self.symmetric_state.mixKey(&self.re.?);
                        }
                        msg_idx += DH.KeyPair.DHLEN;
                    },
                    .s => {
                        const len: usize = if (self.symmetric_state.cipher_state.hasKey()) DH.KeyPair.DHLEN + 16 else DH.KeyPair.DHLEN;

                        _ = try self.symmetric_state.decryptAndHash(self.allocator, self.rs.?[0..], message[msg_idx .. msg_idx + len]);
                        msg_idx += len;
                    },
                    .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                    .es => {
                        var keypair = if (self.role == .Initiator) self.e else self.s;
                        const ikm = if (self.role == .Initiator) self.rs else self.re;
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .se => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                    .psk => {
                        // no-op
                        //
                        try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                        // self.psk_idx += 1;
                    },
                }
            }
        }

        var plaintext: [MAX_MESSAGE_LEN]u8 = undefined;
        const h = try self.symmetric_state.decryptAndHash(self.allocator, plaintext[0 .. message.len - msg_idx], message[msg_idx..message.len]);
        try payload_buf.appendSlice(h);

        if (self.message_patterns.isFinished()) return try self.symmetric_state.split();
        return null;
    }

    pub fn getHandshakeHash(self: *Self) []const u8 {
        return self.symmetric_state.h.constSlice();
    }

    /// Release all allocated memory.
    pub fn deinit(self: *Self) void {
        self.message_patterns.deinit(self.allocator);
        if (self.psks) |psks| {
            self.allocator.free(psks);
        }
    }
};
