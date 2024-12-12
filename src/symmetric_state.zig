const std = @import("std");

const Allocator = std.mem.Allocator;

const CipherState = @import("./cipher.zig").CipherState;
const Hash = @import("hash.zig").Hash;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub fn SymmetricState(comptime H: type) type {
    const Hash_ = Hash(H);

    const HASHLEN = Hash_.len;

    return struct {
        allocator: Allocator,
        cipher_choice: [10]u8,
        cipher_state: CipherState,
        ck: [HASHLEN]u8,
        h: [HASHLEN]u8,

        const Self = @This();

        pub fn init(allocator: Allocator, protocol_name: []const u8) !Self {
            var h: [HASHLEN]u8 = undefined;
            var ck: [HASHLEN]u8 = undefined;
            if (protocol_name.len <= HASHLEN) {
                var data: [HASHLEN]u8 = undefined;
                @memcpy(data[0..protocol_name.len], protocol_name[0..]);
                for (protocol_name.len..HASHLEN) |i| {
                    data[i] = 0;
                }
                @memcpy(&h, &data);
            } else {
                h = Hash_.hash(protocol_name);
            }
            var split_it = std.mem.splitScalar(u8, protocol_name, '_');
            _ = split_it.next().?;
            _ = split_it.next().?;
            _ = split_it.next().?;
            var cipher_choice: [10]u8 = undefined;
            std.mem.copyForwards(u8, &cipher_choice, split_it.next().?);
            std.debug.print("protocol = {s}\n", .{protocol_name});

            const cipher_state = CipherState.init(&cipher_choice, allocator, [_]u8{0} ** 32);

            @memcpy(&ck, &h);
            return .{
                .allocator = allocator,
                .cipher_choice = cipher_choice,
                .cipher_state = cipher_state,
                .ck = ck,
                .h = h,
            };
        }

        pub fn mixKey(
            self: *Self,
            input_key_material: []const u8,
        ) !void {
            // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
            // If HASHLEN is 64, then truncates temp_k to 32 bytes.
            // Calls InitializeKey(temp_k).
            const output = try Hash_.HKDF(self.allocator, &self.ck, input_key_material, 2);

            self.ck = output[0];
            const temp_k = if (HASHLEN == 64) output[1][0..32] else output[1];
            self.cipher_state = CipherState.init(&self.cipher_choice, self.allocator, temp_k);
        }

        pub fn mixHash(self: *Self, data: []const u8) !void {
            const h_with_data = try std.mem.concat(self.allocator, u8, &[_][]const u8{ self.h[0..], data });
            defer self.allocator.free(h_with_data);
            self.h = Hash_.hash(h_with_data);
        }

        /// Used for pre-shared symmetric key (or PSK) mode to support protocols where both parties
        /// have a 32-byte shared secret key.
        pub fn mixKeyAndHash(self: *Self, input_key_material: []const u8) void {
            const output = Hash_.HKDF(self.allocator, self.ck, input_key_material, 2);

            self.ck = output[0];
            self.mixHash(output[1]);
            const temp_k = if (HASHLEN == 64) output[2][0..32] else output[1];
            self.cipher_state.init(temp_k);
        }

        pub fn getHandshakeHash(self: Self) []const u8 {
            return self.h;
        }

        pub fn encryptAndHash(self: *Self, plaintext: []const u8) ![]const u8 {
            //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
            const ciphertext = try self.cipher_state.encryptWithAd(&self.h, plaintext);
            try self.mixHash(ciphertext);
            return ciphertext;
        }

        pub fn decryptAndHash(self: *Self, ciphertext: []const u8) ![]const u8 {
            //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
            const plaintext = try self.cipher_state.decryptWithAd(&self.h, ciphertext);
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
            const output = try Hash_.HKDF(self.allocator, &self.ck, &[_]u8{}, 2);

            const temp_k1 = if (HASHLEN == 64) output[0][0..32] else output[0];
            const temp_k2 = if (HASHLEN == 64) output[1][0..32] else output[1];

            const c1 = CipherState.init(&self.cipher_choice, self.allocator, temp_k1);
            const c2 = CipherState.init(&self.cipher_choice, self.allocator, temp_k2);

            return .{ c1, c2 };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }
    };
}

test "init symmetric state" {
    var symmetric_state = try SymmetricState(Sha256).init(
        std.testing.allocator,
        "Noise_XX_25519_AESGCM_SHA256",
    );
    defer symmetric_state.deinit();
}
