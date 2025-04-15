const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const handshake_pattern = @import("handshake_pattern.zig");
const cipher = @import("cipher.zig");
const Hash = @import("hash.zig").Hash;
const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const DH = @import("dh.zig").DH;
const MAX_MESSAGE_LEN = @import("root.zig").MAX_MESSAGE_LEN;

const CipherState = cipher.CipherState;
const Cipher = cipher.Cipher;
const HandshakePatternName = handshake_pattern.HandshakePatternName;
const HandshakePattern = handshake_pattern.HandshakePattern;
const patternFromName = handshake_pattern.patternFromName;
const MessagePatternArray = handshake_pattern.MessagePatternArray;

//Noise provides a pre-shared symmetric key or PSK mode to support protocols where both parties have a 32-byte shared secret key.
const PSK_SIZE = 32;

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

    psk_idx: usize = 0,

    symmetric_state: SymmetricState,

    const Keys = struct {
        /// The local static key pair
        s: ?DH.KeyPair = null,

        /// The local ephemeral key pair
        e: ?DH.KeyPair = null,

        /// rs: The remote party's static public key
        rs: ?[DH.KeyPair.public_length]u8 = null,

        /// re: The remote party's ephemeral public key
        re: ?[DH.KeyPair.public_length]u8 = null,
    };

    /// Initializes a handshake state machine.
    ///
    /// Deinitialize with `deinit`.
    pub fn initName(
        protocol_name: []const u8,
        allocator: Allocator,
        role: Role,
        prologue: []const u8,
        psks: ?[]const u8,
        keys: Keys,
    ) !Self {
        var sym = try SymmetricState.init(allocator, protocol_name);
        try sym.mixHash(prologue);

        var split_it = std.mem.splitAny(u8, protocol_name, "_");
        _ = split_it.next().?;
        const pattern_name = split_it.next().?;
        const pattern = try patternFromName(allocator, pattern_name);

        // Rules for hashing pre-messages:
        // 1) Initiator's public keys are always hashed first.
        // 2) If multiple public keys are listed, they are hashed in the order that they are listed.
        if (role == .Initiator) {
            if (pattern.pre_message_pattern_initiator) |i| {
                switch (i) {
                    .s => if (keys.s) |s| try sym.mixHashBounded(&s.inner.public_key),
                    .e => if (keys.e) |e| try sym.mixHashBounded(&e.inner.public_key),
                    else => return error.InvalidPreMessagePattern,
                }
            }
            if (pattern.pre_message_pattern_responder) |r| {
                switch (r) {
                    .s => if (keys.rs) |rs| try sym.mixHashBounded(&rs),
                    .e => if (keys.re) |re| try sym.mixHashBounded(&re),
                    else => return error.InvalidPreMessagePattern,
                }
            }
        } else {
            if (pattern.pre_message_pattern_initiator) |i| {
                switch (i) {
                    .s => if (keys.rs) |rs| try sym.mixHashBounded(&rs),
                    .e => if (keys.re) |re| try sym.mixHashBounded(&re),
                    else => return error.InvalidPreMessagePattern,
                }
            }
            if (pattern.pre_message_pattern_responder) |r| {
                switch (r) {
                    .s => if (keys.s) |s| try sym.mixHashBounded(&s.inner.public_key),
                    .e => if (keys.e) |e| try sym.mixHashBounded(&e.inner.public_key),
                    else => return error.InvalidPreMessagePattern,
                }
            }
        }

        return .{
            .allocator = allocator,
            .message_patterns = pattern.message_patterns,
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

                        if (self.psks) |psks| if (psks.len > 0) try self.symmetric_state.mixKey(&pubkey);
                    },
                    .s => {
                        var ciphertext: [48]u8 = undefined;
                        try message.appendSlice(try self.symmetric_state.encryptAndHash(&ciphertext, &self.s.?.inner.public_key));
                    },
                    .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                    .es => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .se => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                    .psk => {
                        try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                        self.psk_idx += 1;
                    },
                }
            }
        }

        var ciphertext: [MAX_MESSAGE_LEN]u8 = undefined;
        const h = try self.symmetric_state.encryptAndHash(&ciphertext, payload);
        try message.appendSlice(ciphertext[0..h.len]);
        if (self.message_patterns.isFinished()) return try self.symmetric_state.split();

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
                        if (!builtin.is_test) std.debug.assert(self.re == null);
                        self.re = undefined;
                        @memcpy(self.re.?[0..], message[msg_idx .. msg_idx + DH.KeyPair.DHLEN]);
                        try self.symmetric_state.mixHashBounded(&self.re.?);

                        if (self.psks) |psks| if (psks.len > 0) try self.symmetric_state.mixKey(&self.re.?);
                        msg_idx += DH.KeyPair.DHLEN;
                    },
                    .s => {
                        const len: usize = if (self.symmetric_state.cipher_state.hasKey()) DH.KeyPair.DHLEN + 16 else DH.KeyPair.DHLEN;

                        if (!builtin.is_test) {
                            std.debug.assert(self.rs == null);
                            self.rs = undefined;
                        }
                        _ = try self.symmetric_state.decryptAndHash(self.rs.?[0..], message[msg_idx .. msg_idx + len]);
                        msg_idx += len;
                    },
                    .ee => try self.symmetric_state.mixKey(&try self.e.?.DH(self.re.?)),
                    .es => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.e, self.rs } else .{ self.s, self.re };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .se => {
                        var keypair, const ikm = if (self.role == .Initiator) .{ self.s, self.re } else .{ self.e, self.rs };
                        try self.symmetric_state.mixKey(&try keypair.?.DH(ikm.?));
                    },
                    .ss => try self.symmetric_state.mixKey(&try self.s.?.DH(self.rs.?)),
                    .psk => {
                        try self.symmetric_state.mixKeyAndHash(self.psks.?[self.psk_idx * PSK_SIZE .. (self.psk_idx + 1) * PSK_SIZE]);
                        self.psk_idx += 1;
                    },
                }
            }
        }

        var plaintext: [MAX_MESSAGE_LEN]u8 = undefined;
        const h = try self.symmetric_state.decryptAndHash(plaintext[0 .. message.len - msg_idx], message[msg_idx..message.len]);
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
        self.symmetric_state.buffer.deinit();
        if (self.psks) |psks| self.allocator.free(psks);
    }
};
