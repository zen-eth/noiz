const std = @import("std");

const Allocator = std.mem.Allocator;

const CipherState = @import("./cipher.zig").CipherState;
const Hash = @import("./root.zig").Hash;

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub fn SymmetricState(comptime H: type, comptime C: type) type {
    const Hash_ = Hash(H);

    const HASHLEN = Hash_.len;

    return struct {
        cipher_state: CipherState(C),
        ck: [HASHLEN]u8,
        h: [HASHLEN]u8,

        const Self = @This();

        pub fn init(allocator: Allocator, protocol_name: []const u8) Self {
            const h = if (protocol_name.len <= HASHLEN) {} else {
                Hash_.hash(protocol_name, .{});
            };

            const cipher_state = CipherState(C, allocator);
            cipher_state.init([_]u8{0} ** 32);
            return .{
                .cipher_state = cipher_state,
                .ck = h,
                .h = h,
            };
        }

        pub fn mixKey(
            self: *Self,
            allocator: Allocator,
            input_key_material: []const u8,
        ) void {
            // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
            // If HASHLEN is 64, then truncates temp_k to 32 bytes.
            // Calls InitializeKey(temp_k).
            const output = Hash_.HKDF(allocator, self.ck, input_key_material, 2);

            self.ck = output[0];
            const temp_k = if (HASHLEN == 64) output[1][0..32] else output[1];
            self.cipher_state.init(temp_k);
        }

        pub fn mixHash(self: *Self, allocator: Allocator, data: []const u8) void {
            const h_with_data = std.mem.concat(allocator, u8, [_][]const u8{ self.h, data });
            defer allocator.free(h_with_data);
            self.h = Hash_.hash(h_with_data);
        }

        /// Used for pre-shared symmetric key (or PSK) mode to support protocols where both parties
        /// have a 32-byte shared secret key.
        pub fn mixKeyAndHash(self: *Self, allocator: Allocator, input_key_material: []const u8) void {
            const output = Hash_.HKDF(allocator, self.ck, input_key_material, 2);

            self.ck = output[0];
            self.mixHash(output[1]);
            const temp_k = if (HASHLEN == 64) output[2][0..32] else output[1];
            self.cipher_state.init(temp_k);
        }

        pub fn getHandshakeHash(self: Self) []const u8 {
            return self.h;
        }

        pub fn encryptAndHash(self: *Self, allocator: Allocator, plaintext: []const u8) void {
            //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
            const ciphertext = self.cipher_state.encryptWithAd(self.h, plaintext);
            self.mixHash(allocator, ciphertext);
            return ciphertext;
        }

        pub fn decryptAndHash(self: *Self, allocator: Allocator, ciphertext: []const u8) void {
            //Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
            const plaintext = self.cipher_state.decryptWithAd(self.h, ciphertext);
            self.mixHash(allocator, ciphertext);
            return plaintext;
        }

        pub fn split(
            self: *Self,
            allocator: Allocator,
            input_key_material: []const u8,
        ) struct { type, type } {
            //
            //    Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
            //    If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
            //    Creates two new CipherState objects c1 and c2.
            //    Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
            //    Returns the pair (c1, c2).
            const output = Hash_.HKDF(allocator, self.ck, input_key_material, 2);

            const temp_k1 = if (HASHLEN == 64) output[0][0..32] else output[0];
            const temp_k2 = if (HASHLEN == 64) output[1][0..32] else output[1];

            var c1 = CipherState(C, allocator);
            var c2 = CipherState(C, allocator);
            c1.init(temp_k1);
            c2.init(temp_k2);

            return .{ c1, c2 };
        }
    };
}

test "init symmetric state" {
    const symmetric_state = SymmetricState(Sha256, ChaCha20Poly1305);
    std.debug.print("symm = {any}", .{symmetric_state});
}
