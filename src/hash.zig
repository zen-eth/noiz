//! Contains the implementation for the Noise hash function.
//!
//! Supports the officially listed hash functions: Sha256, Sha512, BLAKE2s and BLAKE2b.
//!
//! See:
//! http://www.noiseprotocol.org/noise.html#hash-functions
//! https://github.com/ziglang/zig/issues/22101
const std = @import("std");

const sha2 = std.crypto.hash.sha2;
const blake2 = std.crypto.hash.blake2;

pub const HashChoice = enum {
    SHA256,
    SHA512,
    BLAKE2s,
    BLAKE2b,
};

pub const Sha256 = Hash(sha2.Sha256);
pub const Sha512 = Hash(sha2.Sha512);
pub const Blake2s = Hash(blake2.Blake2s256);
pub const Blake2b = Hash(blake2.Blake2b512);

/// The maximum `HASHLEN` that Noise hash functions output.
pub const MAXHASHLEN = 64;

/// Instantiates a Noise hash function.
///
/// Only these hash functions are supported in accordance with the spec: `Sha256`, `Sha512`, `Blake2s256`, `Blake2b512`.
///
/// See: https://noiseprotocol.org/noise.html#hash-functions
pub fn Hash(comptime H: type) type {
    const HASHLEN = comptime switch (H) {
        sha2.Sha256, blake2.Blake2s256 => 32,
        sha2.Sha512, blake2.Blake2b512 => MAXHASHLEN,
        else => @compileError(std.fmt.comptimePrint("Unsupported hash: {any}", .{H})),
    };

    return struct {
        const Self = @This();

        /// Hashes some arbitrary-length `input` with a collision-resistant cryptographic hash function.
        ///
        /// Returns an output of `HASHLEN` bytes.
        pub fn hash(input: []const u8) [HASHLEN]u8 {
            var out: [HASHLEN]u8 = undefined;
            H.hash(input, &out, .{});
            return out;
        }

        /// A mechanism for message authentication using cryptographic hash functions.
        ///
        /// See: https://www.ietf.org/rfc/rfc2104.txt
        fn hmacHash(key: []const u8, data: []const u8) [HASHLEN]u8 {
            var out: [HASHLEN]u8 = undefined;
            std.crypto.auth.hmac.Hmac(H).create(&out, data, key);
            return out;
        }

        /// The HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
        ///
        /// A key derivation function takes some source of initial keying material and derive from it one or more
        /// cryptographically strong secret keys.
        ///
        /// The `chaining_key` serves as the HKDF salt, and zero-length HKDF info.
        ///
        /// Returns a pair or triple of byte sequences each of length `HASHLEN`, depending on whether `num_outputs`
        /// is two or three.
        pub fn HKDF(
            chaining_key: []const u8,
            input_key_material: []const u8,
            num_outputs: u8,
        ) struct { [HASHLEN]u8, [HASHLEN]u8, ?[HASHLEN]u8 } {
            std.debug.assert(chaining_key.len == HASHLEN);
            std.debug.assert(input_key_material.len == 0 or input_key_material.len == 32 or input_key_material.len == HASHLEN);

            const temp_key = hmacHash(chaining_key, input_key_material);
            std.debug.assert(temp_key.len == HASHLEN);
            const output1 = hmacHash(&temp_key, &[_]u8{0x01});
            var data: [HASHLEN + 1]u8 = undefined;

            @memcpy(data[0..HASHLEN], output1[0..]);
            data[HASHLEN] = 0x02;

            const output2 = hmacHash(&temp_key, &data);
            if (num_outputs == 2) return .{ output1, output2, null };

            data = undefined;
            @memcpy(data[0..HASHLEN], output2[0..]);
            data[HASHLEN] = 0x03;
            const output3 = hmacHash(&temp_key, &data);

            return .{ output1, output2, output3 };
        }
    };
}

test "hmacHash" {
    const h = Hash(sha2.Sha256);
    const key = [_]u8{0x0b} ** 20;
    const data = "Hi There";
    const digest = h.hmacHash(&key, data);
    const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    var expected_bytes: [sha2.Sha256.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_bytes, expected);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &digest);
}

test "hash" {
    const h = Hash(sha2.Sha256);
    const ck = [_]u8{1} ** 32;
    const ikm = [_]u8{0x0b} ** 32;
    const allocator = std.testing.allocator;
    const output = h.HKDF(&ck, &ikm, 3);
    if (output[2]) |o| {
        errdefer allocator.free(&o);
    }
}
