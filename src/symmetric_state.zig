//! Contains the implementation for the symmetric state object.
//!
//! See: http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
const std = @import("std");

const BoundedArray = std.BoundedArray;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const CipherState = @import("./cipher.zig").CipherState;
const CipherChoice = @import("./cipher.zig").CipherChoice;

const Hash = @import("hash.zig").Hash;
const MAXHASHLEN = @import("hash.zig").MAXHASHLEN;
const HashSha256 = @import("hash.zig").HashSha256;
const HashSha512 = @import("hash.zig").HashSha512;
const HashBlake2b = @import("hash.zig").HashBlake2b;
const HashBlake2s = @import("hash.zig").HashBlake2s;
const HashChoice = @import("hash.zig").HashChoice;

const MAX_MESSAGE_LEN = @import("handshake_state.zig").MAX_MESSAGE_LEN;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Protocol = struct {
    const Self = @This();

    pattern: []const u8,
    dh: []const u8,
    cipher: CipherChoice,
    hash: HashChoice,
};

// Constructs a `Protocol` from a `protocol_name` byte sequence.
pub fn protocolFromName(protocol_name: []const u8) Protocol {
    var split_it = std.mem.splitScalar(u8, protocol_name, '_');
    _ = split_it.next().?;
    const pattern = split_it.next().?;
    const dh = split_it.next().?;
    const cipher = std.meta.stringToEnum(CipherChoice, split_it.next().?).?;
    const hash = std.meta.stringToEnum(HashChoice, split_it.next().?).?;
    std.debug.assert(split_it.next() == null);

    return .{
        .pattern = pattern,
        .dh = dh,
        .cipher = cipher,
        .hash = hash,
    };
}

pub const SymmetricState = struct {
    cipher_choice: [10]u8,
    cipher_state: CipherState,
    ck: BoundedArray(u8, MAXHASHLEN),
    h: BoundedArray(u8, MAXHASHLEN),

    hasher: Hasher,

    /// An internal buffer used for storing variable-length data during `mixHash`.
    /// This is reused throughout handshake / transport in order to save on allocations.
    buffer: ArrayList(u8),

    const Self = @This();

    const Hasher = struct {
        choice: HashChoice,
        len: usize,

        fn hash(self: *Hasher, input: []const u8) !BoundedArray(u8, MAXHASHLEN) {
            var out = BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable;
            if (self.choice == .SHA256 or self.choice == .BLAKE2s) {
                const hash_out = switch (self.choice) {
                    .SHA256 => HashSha256.hash(input),
                    .BLAKE2s => HashBlake2s.hash(input),
                    else => @panic("Hash not set"),
                };
                try out.appendSlice(&hash_out);
            } else {
                const hash_out = switch (self.choice) {
                    .SHA512 => HashSha512.hash(input),
                    .BLAKE2b => HashBlake2b.hash(input),
                    else => @panic("Hash not set"),
                };
                try out.appendSlice(&hash_out);
            }

            return out;
        }

        fn HKDF(
            self: *Hasher,
            chaining_key: []const u8,
            input_key_material: []const u8,
            num_outputs: u8,
        ) !struct {
            BoundedArray(u8, MAXHASHLEN),
            BoundedArray(u8, MAXHASHLEN),
            ?BoundedArray(u8, MAXHASHLEN),
        } {
            std.debug.assert(chaining_key.len == self.len);
            std.debug.assert(input_key_material.len == 0 or input_key_material.len == 32);

            var out1 = BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable;
            var out2 = BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable;
            var out3: ?BoundedArray(u8, MAXHASHLEN) = if (num_outputs == 3) BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable else null;

            if (self.choice == .SHA256) {
                const hkdf_out = HashSha256.HKDF(chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .BLAKE2s) {
                const hkdf_out = HashBlake2s.HKDF(chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .SHA512) {
                const hkdf_out =
                    HashSha512.HKDF(chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .BLAKE2b) {
                const hkdf_out = HashBlake2b.HKDF(chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            }

            return .{ out1, out2, out3 };
        }
    };

    pub fn init(allocator: Allocator, protocol_name: []const u8) !Self {
        const protocol = protocolFromName(protocol_name);

        const hash_len: usize = switch (protocol.hash) {
            .SHA256, .BLAKE2s => 32,
            .SHA512, .BLAKE2b => MAXHASHLEN,
        };

        var hasher = Hasher{ .len = hash_len, .choice = protocol.hash };

        var h = BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable;
        var ck = BoundedArray(u8, MAXHASHLEN).init(0) catch unreachable;
        if (protocol_name.len <= hash_len) {
            var data: [MAXHASHLEN]u8 = undefined;
            @memcpy(data[0..protocol_name.len], protocol_name[0..protocol_name.len]);
            for (protocol_name.len..hash_len) |i| {
                data[i] = 0;
            }
            try h.appendSlice(data[0..hash_len]);
        } else {
            h = try hasher.hash(protocol_name);
        }

        // Noise protocol names are always in the format Noise_<PATTERN_NAME>_<CURVE>_<CIPHER>_<HASH>.
        var split_it = std.mem.splitScalar(u8, protocol_name, '_');
        _ = split_it.next().?; // Noise
        _ = split_it.next().?; // <PATTERN_NAME>
        _ = split_it.next().?; // <CURVE>
        var cipher_choice = [_]u8{0} ** 10;
        const cipher_choice_str = split_it.next().?; // <CIPHER>
        @memcpy(cipher_choice[0..cipher_choice_str.len], cipher_choice_str);

        const cipher_state = try CipherState.init(&cipher_choice, [_]u8{0} ** 32);
        try ck.appendSlice(h.constSlice());

        return .{
            .cipher_choice = cipher_choice,
            .cipher_state = cipher_state,
            .ck = ck,
            .h = h,
            .hasher = hasher,
            .buffer = try ArrayList(u8).initCapacity(allocator, MAX_MESSAGE_LEN),
        };
    }

    pub fn mixKey(
        self: *Self,
        input_key_material: []const u8,
    ) !void {
        // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        // If HASHLEN is MAXHASHLEN, then truncates temp_k to 32 bytes.
        // Calls InitializeKey(temp_k).
        const output = try self.hasher.HKDF(self.ck.constSlice(), input_key_material, 2);

        self.ck = output[0];
        var temp_k: [32]u8 = undefined;
        @memcpy(&temp_k, output[1].constSlice()[0..32]);
        self.cipher_state = try CipherState.init(&self.cipher_choice, temp_k);
    }

    /// Mix hash with a variable-length `data` input.
    ///
    /// This is for use in (1) mixing prologue or (2) encryption/decryption, since
    /// the payloads are of variable-length.
    ///
    /// For mixing with cipher keys or hash digests, we use `mixHashBounded`.
    pub fn mixHash(self: *Self, data: []const u8) !void {
        try self.buffer.appendSlice(self.h.constSlice());
        try self.buffer.appendSlice(data);
        self.h = try self.hasher.hash(self.buffer.items);
        self.buffer.clearRetainingCapacity();
    }

    /// The no-alloc version of `mixHash`. This is for mixing data of bounded length:
    /// We know that we use `mixHash` possibly with
    /// (1) cipher keys (32 bytes), or
    /// (2) hash digests (32 or 64 bytes),
    ///
    /// So we use a `BoundedArray` of a maximum of 128 bytes instead of using `std.mem.concat` for these use cases.
    pub fn mixHashBounded(self: *Self, data: []const u8) !void {
        // MAXHASHLEN + max possible HKDF output (64) = 128 bytes
        var h_with_data = try std.BoundedArray(u8, 128).init(0);
        try h_with_data.appendSlice(self.h.constSlice());
        try h_with_data.appendSlice(data);
        self.h = try self.hasher.hash(h_with_data.constSlice());
    }

    /// Used for pre-shared symmetric key (or PSK) mode to support protocols where both parties
    /// have a 32-byte shared secret key.
    pub fn mixKeyAndHash(self: *Self, input_key_material: []const u8) !void {
        const output = try self.hasher.HKDF(self.ck.constSlice(), input_key_material, 3);

        self.ck = output[0];
        try self.mixHashBounded(output[1].constSlice());
        var temp_k: [32]u8 = undefined;
        @memcpy(&temp_k, output[2].?.constSlice()[0..32]);
        self.cipher_state = try CipherState.init(&self.cipher_choice, temp_k);
    }

    pub fn encryptAndHash(self: *Self, ciphertext: []u8, plaintext: []const u8) ![]const u8 {
        //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
        const slice = try self.cipher_state.encryptWithAd(ciphertext, self.h.constSlice(), plaintext);
        try self.mixHash(slice);
        return slice;
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn decryptAndHash(self: *Self, plaintext: []u8, ciphertext: []const u8) ![]const u8 {
        const decrypted = try self.cipher_state.decryptWithAd(plaintext, self.h.constSlice(), ciphertext);
        try self.mixHash(ciphertext);
        return decrypted;
    }

    pub fn split(
        self: *Self,
    ) !struct { CipherState, CipherState } {
        const output = try self.hasher.HKDF(self.ck.constSlice(), &[_]u8{}, 2);

        var temp_k1: [32]u8 = undefined;
        var temp_k2: [32]u8 = undefined;
        @memcpy(&temp_k1, output[0].constSlice()[0..32]);
        @memcpy(&temp_k2, output[1].constSlice()[0..32]);

        const c1 = try CipherState.init(&self.cipher_choice, temp_k1);
        const c2 = try CipherState.init(&self.cipher_choice, temp_k2);

        return .{ c1, c2 };
    }
};

test "init symmetric state" {
    const allocator = std.testing.allocator;
    var symmetric_state = try SymmetricState.init(allocator, "Noise_XX_25519_AESGCM_SHA256");
    defer symmetric_state.buffer.deinit();

    const ck = [_]u8{1} ** 32;
    const ikm = [_]u8{};
    const output = try symmetric_state.hasher.HKDF(&ck, &ikm, 3);
    errdefer allocator.free(&output[0]);
}
