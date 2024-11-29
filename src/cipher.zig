const std = @import("std");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Allocator = std.mem.Allocator;
const testing = std.testing;

pub fn CipherState(comptime C: type, allocator: Allocator) type {
    const Cipher_ = Cipher(C);

    return struct {
        k: [32]u8,
        n: u64,

        const Self = @This();

        pub fn init(key: [32]u8) Self {
            return .{ .k = key, .n = 0 };
        }

        pub fn hasKey(self: *Self) bool {
            return self.k != [_]u8{0} ** 32;
        }

        pub fn setNonce(self: *Self, nonce: u64) void {
            self.n = nonce;
        }

        pub fn encryptWithAd(self: *const Self, ad: []const u8, plaintext: []const u8) ![]const u8 {
            return try Cipher_.encrypt(allocator, self.k, self.n, ad, plaintext);
        }

        pub fn decryptWithAd(self: *const Self, ad: []const u8, ciphertext: []const u8) ![]const u8 {
            return try Cipher_.decrypt(allocator, self.k, self.n, ad, ciphertext);
        }
    };
}

/// Instantiates a Noise cipher function.
///
/// Only these ciphers are supported in accordance with the spec: `Aes256Gcm`, `ChaCha20Poly1305`.
///
/// https://noiseprotocol.org/noise.html#cipher-functions
// TODO: implement rekey
fn Cipher(comptime C: type) type {
    comptime switch (C) {
        Aes256Gcm, ChaCha20Poly1305 => {},
        else => @compileError(std.fmt.comptimePrint("Unsupported cipher: {any}", .{C})),
    };

    const Cipher_ = C;

    return struct {
        const tag_length = Cipher_.tag_length;
        const nonce_length = Cipher_.nonce_length;
        const key_length = Cipher_.key_length;

        /// Encrypts `plaintext` using the cipher key `k` of 32 bytes and an 8-byte unsigned integer nonce `n` which must be unique for the key `k`.
        ///
        /// Returns the ciphertext that is the same length as the plaintext with the 16-byte authentication tag appended.
        fn encrypt(
            allocator: Allocator,
            k: [key_length]u8,
            n: u64,
            ad: []const u8,
            plaintext: []const u8,
        ) ![]const u8 {
            var tag: [tag_length]u8 = undefined;
            const ciphertext = try allocator.alloc(u8, plaintext.len + tag_length);
            errdefer allocator.free(ciphertext);
            var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;
            const n_bytes: [8]u8 = @bitCast(n);

            @memcpy(nonce[nonce_length - @sizeOf(u64) .. nonce_length], &n_bytes);
            Cipher_.encrypt(ciphertext[0..plaintext.len], tag[0..], plaintext, ad, nonce, k);

            @memcpy(ciphertext[plaintext.len .. plaintext.len + tag_length], &tag);
            return ciphertext;
        }

        /// Decrypts `ciphertext` using a cipher key `k` of 32-bytes, an 8-byte unsigned integer nonce `n`, and associated data `ad`.
        ///
        /// Returns the plaintext, unless authentication fails, in which case an error is signaled to the caller.
        fn decrypt(
            allocator: Allocator,
            k: [key_length]u8,
            n: u64,
            ad: []const u8,
            ciphertext: []const u8,
        ) ![]const u8 {
            const plaintext = try allocator.alloc(u8, ciphertext.len - tag_length);
            errdefer allocator.free(plaintext);

            var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;

            const n_bytes: [8]u8 = @bitCast(n);

            // If `Aes256Gcm` is used, we use big-endian encoding of n.
            if (Cipher_ == Aes256Gcm) {
                std.mem.reverse(u8, n_bytes);
            }

            @memcpy(nonce[nonce_length - @sizeOf(u64) .. nonce_length], &n_bytes);
            var tag: [tag_length]u8 = [_]u8{0} ** tag_length;
            @memcpy(&tag, ciphertext[plaintext.len..]);
            try Cipher_.decrypt(plaintext, ciphertext[0..plaintext.len], tag, ad, nonce, k);

            return plaintext;
        }
    };
}

test "cipher and cipherstate consistency" {
    const allocator = std.testing.allocator;

    const key = [_]u8{69} ** 32;
    const cipher_state = CipherState(ChaCha20Poly1305, allocator).init(key);
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    const ciphertext = try cipher_state.encryptWithAd(ad, m);
    defer allocator.free(ciphertext[0..]);
    const plaintext = try cipher_state.decryptWithAd(ad[0..], ciphertext);
    defer allocator.free(plaintext[0..]);

    try testing.expectEqualSlices(u8, plaintext[0..], m);
}
