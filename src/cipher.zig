const std = @import("std");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const Allocator = std.mem.Allocator;
const testing = std.testing;

const CipherError = error{
    /// Nonce is exhausted once it reaches (2^64) - 1.
    ///
    /// This means parties are not allowed to send more than (2^64)-1 transport messages.
    NonceExhaustion,
    OutOfMemory,
    AuthenticationFailed,
};

/// spec: https://noiseprotocol.org/noise.html#the-cipherstate-object
pub fn CipherState(comptime C: type) type {
    const Cipher_ = Cipher(C);

    return struct {
        allocator: Allocator, 
        /// A cipher key of 32 bytes (which may be empty).
        ///
        /// Empty is a special value which indicates `k` has not yet been initialized.
        k: [32]u8 = [_]u8{0} ** 32,

        /// An 8-byte (64-bit) unsigned integer nonce.
        n: u64,

        const Self = @This();

        /// Sets `k` = `key` and `n` = 0.
        pub fn init(allocator: Allocator, key: [32]u8) Self {
            return .{ .allocator = allocator, .k = key, .n = 0 };
        }

        /// Returns true if `k` is non-empty, false otherwise.
        pub fn hasKey(self: *Self) bool {
            return !std.mem.eql(u8, &self.k, &[_]u8{0} ** 32);
        }

        /// Sets `n` = `nonce`. This i used for handling out-of-order transport messages.
        /// See: https://noiseprotocol.org/noise.html#out-of-order-transport-messages
        pub fn setNonce(self: *Self, nonce: u64) void {
            self.n = nonce;
        }

        /// If `k` is non-empty returns `Cipher_.encrypt(k, n++, ad, plaintext). Otherwise return plaintext.
        pub fn encryptWithAd(self: *Self, ad: []const u8, plaintext: []const u8) CipherError![]const u8 {
            if (!self.hasKey()) return plaintext;
            if (self.n == std.math.maxInt(u64) - 1) return error.NonceExhaustion;

            const ciphertext = Cipher_.encrypt(self.allocator, self.k, self.n, ad, plaintext) catch |err| {
                // Nonce is still incremented if encryption fails.
                // Reusing a nonce value for n with the same key k for encryption would be catastrophic.
                // Nonces are not allowed to wrap back to zero due to integer overflow, and the maximum nonce value is reserved.
                self.n += 1;
                return err;
            };

            self.n += 1;
            return ciphertext;
        }

        pub fn decryptWithAd(self: *Self, ad: []const u8, ciphertext: []const u8) CipherError![]const u8 {
            if (!self.hasKey()) return ciphertext;
            if (self.n == std.math.maxInt(u64) - 1) return error.NonceExhaustion;

            // Nonce is NOT incremented if decryption fails.
            const plaintext = try Cipher_.decrypt(self.allocator, self.k, self.n, ad, ciphertext);
            self.n += 1;

            return plaintext;
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

            var n_bytes: [8]u8 = @bitCast(n);

            // If `Aes256Gcm` is used, we use big-endian encoding of n.
            if (Cipher_ == Aes256Gcm) {
                std.mem.reverse(u8, &n_bytes);
            }

            @memcpy(nonce[nonce_length - @sizeOf(u64) .. nonce_length], &n_bytes);
            var tag: [tag_length]u8 = [_]u8{0} ** tag_length;
            @memcpy(&tag, ciphertext[plaintext.len..]);
            try Cipher_.decrypt(plaintext, ciphertext[0..plaintext.len], tag, ad, nonce, k);

            return plaintext;
        }
    };
}

fn testCipher(comptime C: type) !void {
    const allocator = std.testing.allocator;

    const key = [_]u8{69} ** 32;
    var sender = CipherState(C).init(allocator, key);
    var receiver = CipherState(C).init(allocator, key);
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    const ciphertext = try sender.encryptWithAd(ad, m);
    defer allocator.free(ciphertext[0..]);
    const plaintext = try receiver.decryptWithAd(ad[0..], ciphertext);
    defer allocator.free(plaintext[0..]);

    try testing.expectEqualSlices(u8, plaintext[0..], m);
}

test "cipherstate consistency" {
    _ = try testCipher(ChaCha20Poly1305);
    _ = try testCipher(Aes256Gcm);
}

test "failed encryption returns plaintext" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    var sender = CipherState(ChaCha20Poly1305).init(allocator, key);
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    const retval = try sender.encryptWithAd(ad, m);
    try testing.expectEqualSlices(u8, m[0..], retval);
}

test "encryption fails on max nonce" {
    const allocator = std.testing.allocator;

    const key = [_]u8{1} ** 32;
    var sender = CipherState(ChaCha20Poly1305).init(allocator, key);
    sender.n = std.math.maxInt(u64) - 1;

    const retval = sender.encryptWithAd("", "");
    try testing.expectError(error.NonceExhaustion, retval);
}
