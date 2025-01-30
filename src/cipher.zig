const std = @import("std");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const BoundedArray = std.BoundedArray;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const CipherError = error{
    /// Nonce is exhausted once it reaches (2^64) - 1.
    ///
    /// This means parties are not allowed to send more than (2^64)-1 transport messages.
    NonceExhaustion,
    OutOfMemory,
    Overflow,
    AuthenticationFailed,
};

/// Choice of cipher in a noise protocol. These must be stylized like in the [protocol specification]
/// for `std.meta.stringToEnum` to work as intended.
///
/// [protocol specification]: https://noiseprotocol.org/noise.html#protocol-names-and-modifiers
pub const CipherChoice = enum {
    ChaChaPoly,
    AESGCM,
};

pub const CipherState = union(enum) {
    chacha: CipherState_(ChaCha20Poly1305),
    aesgcm: CipherState_(Aes256Gcm),

    const nonce_length: usize = 12;

    pub fn init(cipher_st: []const u8, key: [32]u8) CipherState {
        const len = std.mem.sliceTo(cipher_st, 0).len;
        const cipher_choice = std.meta.stringToEnum(CipherChoice, cipher_st[0..len]);
        return switch (cipher_choice.?) {
            .ChaChaPoly => CipherState{ .chacha = CipherState_(ChaCha20Poly1305).init(key) },
            .AESGCM => CipherState{ .aesgcm = CipherState_(Aes256Gcm).init(key) },
        };
    }

    pub fn encryptWithAd(self: *CipherState, ciphertext: []u8, ad: []const u8, plaintext: []const u8) ![]const u8 {
        var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;

        switch (self.*) {
            .chacha => {
                const n_bytes: [8]u8 = @bitCast(self.chacha.n);
                for (nonce[nonce_length - @sizeOf(@TypeOf(self.chacha.n)) .. nonce_length], 0..) |*dst, i| {
                    dst.* = n_bytes[i];
                }

                return self.chacha.encryptWithAd(ciphertext, ad, plaintext, nonce);
            },
            .aesgcm => {
                const n_bytes: [8]u8 = @bitCast(self.aesgcm.n);
                for (nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], 0..) |*dst, i| {
                    dst.* = n_bytes[n_bytes.len - i - 1];
                }

                return self.aesgcm.encryptWithAd(ciphertext, ad, plaintext, nonce);
            },
        }
    }

    pub fn decryptWithAd(self: *CipherState, plaintext: []u8, ad: []const u8, ciphertext: []const u8) CipherError![]const u8 {
        switch (self.*) {
            .chacha => return self.chacha.decryptWithAd(plaintext, ad, ciphertext),
            .aesgcm => return self.aesgcm.decryptWithAd(plaintext, ad, ciphertext),
        }
    }

    /// Returns true if `k` is non-empty, false otherwise.
    pub fn hasKey(self: *CipherState) bool {
        switch (self.*) {
            .chacha => return self.chacha.hasKey(),
            .aesgcm => return self.aesgcm.hasKey(),
        }
    }

    pub fn tagLength(self: *CipherState) usize {
        switch (self.*) {
            .chacha => return self.chacha.tagLength(),
            .aesgcm => return self.aesgcm.tagLength(),
        }
    }
};

/// spec: https://noiseprotocol.org/noise.html#the-cipherstate-object
fn CipherState_(comptime C: type) type {
    const Cipher_ = Cipher(C);

    return struct {
        const Self = @This();

        /// A cipher key of 32 bytes (which may be empty).
        ///
        /// Empty is a special value which indicates `k` has not yet been initialized.
        k: [32]u8 = [_]u8{0} ** 32,

        /// An 8-byte (64-bit) unsigned integer nonce.
        n: u64,

        nonce_length: usize = Cipher_.nonce_length,

        /// Sets `k` = `key` and `n` = 0.
        fn init(key: [32]u8) Self {
            return .{ .k = key, .n = 0 };
        }

        /// Returns true if `k` is non-empty, false otherwise.
        fn hasKey(self: *Self) bool {
            return !std.mem.eql(u8, &self.k, &[_]u8{0} ** 32);
        }

        /// Sets `n` = `nonce`. This i used for handling out-of-order transport messages.
        /// See: https://noiseprotocol.org/noise.html#out-of-order-transport-messages
        fn setNonce(self: *Self, nonce: u64) void {
            self.n = nonce;
        }

        /// If `k` is non-empty returns `Cipher_.encrypt(k, n++, ad, plaintext). Otherwise return plaintext.
        fn encryptWithAd(self: *Self, ciphertext: []u8, ad: []const u8, plaintext: []const u8, nonce: [Cipher_.nonce_length]u8) CipherError![]const u8 {
            if (!self.hasKey()) {
                @memcpy(ciphertext[0..plaintext.len], plaintext);
                return ciphertext[0..plaintext.len];
            }
            if (self.n == std.math.maxInt(u64)) return error.NonceExhaustion;

            const slice = Cipher_.encrypt(ciphertext, self.k, nonce, ad, plaintext) catch |err| {
                // Nonce is still incremented if encryption fails.
                // Reusing a nonce value for n with the same key k for encryption would be catastrophic.
                // Nonces are not allowed to wrap back to zero due to integer overflow, and the maximum nonce value is reserved.
                self.n += 1;
                return err;
            };

            self.n += 1;
            return slice;
        }

        pub fn decryptWithAd(self: *Self, plaintext: []u8, ad: []const u8, ciphertext: []const u8) CipherError![]const u8 {
            if (!self.hasKey()) {
                @memcpy(plaintext[0..ciphertext.len], ciphertext);
                return ciphertext;
            }
            if (self.n == std.math.maxInt(u64)) return error.NonceExhaustion;

            // Nonce is NOT incremented if decryption fails.
            const slice = try Cipher_.decrypt(plaintext, self.k, self.n, ad, ciphertext);
            self.n += 1;

            return slice;
        }

        pub fn rekey(self: *Self) !void {
            self.k = try Cipher_.rekey(self.k);
        }

        fn tagLength(_: *Self) usize {
            return Cipher_.tag_length;
        }
    };
}

/// Instantiates a Noise cipher function.
///
/// Only these ciphers are supported in accordance with the spec: `Aes256Gcm`, `ChaCha20Poly1305`.
///
/// https://noiseprotocol.org/noise.html#cipher-functions
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
            ciphertext: []u8,
            k: [key_length]u8,
            nonce: [nonce_length]u8,
            ad: []const u8,
            plaintext: []const u8,
        ) ![]const u8 {
            var tag: [tag_length]u8 = undefined;
            Cipher_.encrypt(ciphertext[0..plaintext.len], tag[0..], plaintext, ad, nonce, k);

            @memcpy(ciphertext[plaintext.len .. plaintext.len + tag_length], &tag);
            return ciphertext[0 .. plaintext.len + tag_length];
        }

        /// Decrypts `ciphertext` using a cipher key `k` of 32-bytes, an 8-byte unsigned integer nonce `n`, and associated data `ad`.
        ///
        /// Returns the plaintext, unless authentication fails, in which case an error is signaled to the caller.
        fn decrypt(
            plaintext: []u8,
            k: [key_length]u8,
            n: u64,
            ad: []const u8,
            ciphertext: []const u8,
        ) ![]const u8 {
            var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;
            const n_bytes: [8]u8 = @bitCast(n);

            for (nonce[4..], 0..) |*dst, i| {
                dst.* = if (C == ChaCha20Poly1305)
                    n_bytes[i]
                else
                    n_bytes[n_bytes.len - i - 1];
            }

            var tag: [tag_length]u8 = undefined;
            @memcpy(tag[0..], ciphertext[ciphertext.len - tag_length .. ciphertext.len]);
            try Cipher_.decrypt(plaintext[0 .. ciphertext.len - tag_length], ciphertext[0 .. ciphertext.len - tag_length], tag, ad, nonce, k);

            return plaintext[0 .. ciphertext.len - tag_length];
        }

        fn rekey(k: [key_length]u8) ![32]u8 {
            var plaintext: [32]u8 = undefined;
            var ciphertext: [48]u8 = undefined;
            const enc = try encrypt(&ciphertext, k, std.math.maxInt(u64), &[_]u8{}, &[_]u8{0} ** 32);
            @memcpy(&plaintext, enc[0..32]);
            return plaintext;
        }
    };
}

fn testCipher(comptime C: type) !void {
    const allocator = std.testing.allocator;

    const key = [_]u8{69} ** 32;
    var sender = CipherState_(C).init(key);
    var receiver = CipherState_(C).init(key);
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    var ciphertext = try allocator.alloc(u8, m.len + 16);
    _ = try sender.encryptWithAd(ciphertext, ad, m);
    defer allocator.free(ciphertext[0..]);

    var plaintext = try allocator.alloc(u8, m.len);
    _ = try receiver.decryptWithAd(plaintext, ad[0..], ciphertext);
    defer allocator.free(plaintext[0..]);

    try testing.expectEqualSlices(u8, plaintext[0..], m);
}

test "cipherstate consistency" {
    _ = try testCipher(ChaCha20Poly1305);
    _ = try testCipher(Aes256Gcm);
}

test "failed encryption returns plaintext" {
    const key = [_]u8{0} ** 32;
    var sender = CipherState_(ChaCha20Poly1305).init(key);
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    const ciphertext = try std.testing.allocator.alloc(u8, m.len + 16);
    defer std.testing.allocator.free(ciphertext);
    const retval = try sender.encryptWithAd(ciphertext, ad, m);
    try testing.expectEqualSlices(u8, m[0..], retval);
}

test "encryption fails on max nonce" {
    const key = [_]u8{1} ** 32;
    var sender = CipherState_(ChaCha20Poly1305).init(key);
    sender.n = std.math.maxInt(u64);

    const retval = sender.encryptWithAd("", "", "");
    try testing.expectError(error.NonceExhaustion, retval);
}

test "rekey" {
    const allocator = std.testing.allocator;

    const key = [_]u8{1} ** 32;
    var sender = CipherState_(ChaCha20Poly1305).init(key);

    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    const ciphertext = try std.testing.allocator.alloc(u8, m.len + 16);
    const ciphertext1 = try sender.encryptWithAd(ciphertext, ad, m);
    defer allocator.free(ciphertext1);

    try sender.rekey();
    const ciphertext2 = try std.testing.allocator.alloc(u8, m.len + 16);
    _ = try sender.encryptWithAd(ciphertext2, ad, m);
    defer allocator.free(ciphertext2);
    // rekeying actually changed keys
    try std.testing.expect(!std.mem.eql(u8, ciphertext1, ciphertext2));
}
