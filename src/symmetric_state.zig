const std = @import("std");

const BoundedArray = std.BoundedArray;

const Allocator = std.mem.Allocator;

const CipherState = @import("./cipher.zig").CipherState;
const CipherChoice = @import("./cipher.zig").CipherChoice;
const Hash = @import("hash.zig").Hash;
const HashSha256 = @import("hash.zig").HashSha256;
const HashSha512 = @import("hash.zig").HashSha512;
const HashBlake2b = @import("hash.zig").HashBlake2b;
const HashBlake2s = @import("hash.zig").HashBlake2s;
const HashChoice = @import("hash.zig").HashChoice;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Protocol = struct {
    const Self = @This();

    pattern: []const u8,
    dh: []const u8,
    cipher: CipherChoice,
    hash: HashChoice,
};

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
    allocator: Allocator,
    cipher_choice: [10]u8,
    cipher_state: CipherState,
    ck: BoundedArray(u8, 64),
    h: BoundedArray(u8, 64),

    hasher: Hasher,

    const Self = @This();

    const Hasher = struct {
        choice: HashChoice,
        len: usize,

        fn hash(self: *Hasher, input: []const u8) !BoundedArray(u8, 64) {
            var out = try BoundedArray(u8, 64).init(0);
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
            allocator: std.mem.Allocator,
            chaining_key: []const u8,
            input_key_material: []const u8,
            num_outputs: u8,
        ) !struct {
            BoundedArray(u8, 64),
            BoundedArray(u8, 64),
            ?BoundedArray(u8, 64),
        } {
            std.debug.assert(chaining_key.len == self.len);
            std.debug.assert(input_key_material.len == 0 or
                input_key_material.len == 32);

            var out1 = try BoundedArray(u8, 64).init(0);
            var out2 = try BoundedArray(u8, 64).init(0);
            var out3: ?BoundedArray(u8, 64) = if (num_outputs == 3) try BoundedArray(u8, 64).init(0) else null;

            if (self.choice == .SHA256) {
                const hkdf_out = try HashSha256.HKDF(allocator, chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .BLAKE2s) {
                const hkdf_out = try HashBlake2s.HKDF(allocator, chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .SHA512) {
                const hkdf_out =
                    try HashSha512.HKDF(allocator, chaining_key, input_key_material, num_outputs);
                try out1.appendSlice(&hkdf_out[0]);
                try out2.appendSlice(&hkdf_out[1]);
                if (out3) |*o| try o.*.appendSlice(&hkdf_out[2].?);
            } else if (self.choice == .BLAKE2b) {
                const hkdf_out = try HashBlake2b.HKDF(allocator, chaining_key, input_key_material, num_outputs);
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
            .SHA512, .BLAKE2b => 64,
        };

        var hasher = Hasher{ .len = hash_len, .choice = protocol.hash };

        var h = try BoundedArray(u8, 64).init(0);
        var ck = try BoundedArray(u8, 64).init(0);
        if (protocol_name.len <= hash_len) {
            var data: [64]u8 = undefined;
            @memcpy(data[0..protocol_name.len], protocol_name[0..protocol_name.len]);
            for (protocol_name.len..hash_len) |i| {
                data[i] = 0;
            }
            try h.appendSlice(data[0..hash_len]);
        } else {
            h = try hasher.hash(protocol_name);
        }
        var split_it = std.mem.splitScalar(u8, protocol_name, '_');
        _ = split_it.next().?;
        _ = split_it.next().?;
        _ = split_it.next().?;
        var cipher_choice = [_]u8{0} ** 10;
        const cipher_choice_st = split_it.next().?;
        std.mem.copyForwards(u8, &cipher_choice, cipher_choice_st);

        const cipher_state = CipherState.init(&cipher_choice, allocator, [_]u8{0} ** 32);
        try ck.appendSlice(h.constSlice());

        return .{
            .allocator = allocator,
            .cipher_choice = cipher_choice,
            .cipher_state = cipher_state,
            .ck = ck,
            .h = h,
            .hasher = hasher,
        };
    }

    pub fn mixKey(
        self: *Self,
        input_key_material: []const u8,
    ) !void {
        // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        // If HASHLEN is 64, then truncates temp_k to 32 bytes.
        // Calls InitializeKey(temp_k).
        const output = try self.hasher.HKDF(self.allocator, self.ck.constSlice(), input_key_material, 2);

        self.ck = output[0];
        var temp_k: [32]u8 = undefined;
        @memcpy(&temp_k, output[1].slice()[0..32]);
        self.cipher_state.deinit();
        self.cipher_state = CipherState.init(&self.cipher_choice, self.allocator, temp_k);
    }

    pub fn mixHash(self: *Self, data: []const u8) !void {
        _ = [_]u8{0} ** 32;
        const h_with_data = try std.mem.concat(self.allocator, u8, &[_][]const u8{ self.h.constSlice(), data });
        defer self.allocator.free(h_with_data);
        self.h = try self.hasher.hash(h_with_data);
    }

    /// Used for pre-shared symmetric key (or PSK) mode to support protocols where both parties
    /// have a 32-byte shared secret key.
    pub fn mixKeyAndHash(self: *Self, input_key_material: []const u8) void {
        const output = self.hasher.HKDF(self.allocator, self.ck.slice(), input_key_material, 2);

        self.ck = output[0];
        self.mixHash(output[1]);
        const temp_k = if (self.hashlen == 64) output[2][0..32] else output[1];
        self.cipher_state.init(temp_k);
    }

    pub fn encryptAndHash(self: *Self, plaintext: []const u8) ![]const u8 {
        //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
        const ciphertext = try self.cipher_state.encryptWithAd(self.h.constSlice(), plaintext);
        try self.mixHash(ciphertext);
        return ciphertext;
    }

    pub fn decryptAndHash(self: *Self, ciphertext: []const u8) ![]const u8 {
        //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
        const plaintext = try self.cipher_state.decryptWithAd(self.h.constSlice(), ciphertext);
        try self.mixHash(ciphertext);

        return plaintext;
    }

    pub fn split(
        self: *Self,
    ) !struct { CipherState, CipherState } {
        //
        //    Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
        //    If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
        //    Creates two new CipherState objects c1 and c2.
        //    Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
        //    Returns the pair (c1, c2).
        const output = try self.hasher.HKDF(self.allocator, self.ck.slice(), &[_]u8{}, 2);

        var temp_k1: [32]u8 = undefined;
        var temp_k2: [32]u8 = undefined;
        if (self.hasher.len == 64) @memcpy(&temp_k1, output[0].slice()[0..32]) else @memcpy(&temp_k1, output[0].slice());
        if (self.hasher.len == 64) @memcpy(&temp_k2, output[1].slice()[0..32]) else @memcpy(&temp_k2, output[1].slice());

        const c1 = CipherState.init(&self.cipher_choice, self.allocator, temp_k1);
        const c2 = CipherState.init(&self.cipher_choice, self.allocator, temp_k2);

        return .{ c1, c2 };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

test "init symmetric state" {
    var symmetric_state = try SymmetricState.init(
        std.testing.allocator,
        "Noise_XX_25519_AESGCM_SHA256",
    );
    const ck = [_]u8{1} ** 32;
    const ikm = [_]u8{};
    const allocator = std.testing.allocator;
    const output = try symmetric_state.hasher.HKDF(allocator, &ck, &ikm, 3);
    errdefer allocator.free(&output[0]);

    defer symmetric_state.deinit();
}
