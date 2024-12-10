const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SymmetricState = @import("symmetric_state.zig").SymmetricState;

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
const Hash = @import("hash.zig").Hash;

const Message = struct {
    payload: []const u8,
    ciphertext: []const u8,
};

const Vector = struct {
    protocol_name: []const u8,
    init_prologue: []const u8,
    init_psks: [][]const u8,
    init_ephemeral: []const u8,
    init_remote_static: ?[]const u8 = null,
    init_static: ?[]const u8 = null,
    resp_prologue: []const u8,
    resp_psks: [][]const u8,
    resp_static: ?[]const u8 = null,
    resp_ephemeral: []const u8,
    resp_remote_static: ?[]const u8 = null,
    messages: []const Message,
};

const Vectors = struct {
    vectors: []const Vector,
};

test "snow" {
    const snow_txt = try std.fs.cwd().openFile("./testdata/snow.txt", .{});
    const buf: []u8 = try snow_txt.readToEndAlloc(std.testing.allocator, 1_000_000);
    defer std.testing.allocator.free(buf);

    // Validate snow.txt is loaded correctly
    try std.testing.expect(try std.json.validate(std.testing.allocator, buf));
    const data = try std.json.parseFromSlice(Vectors, std.testing.allocator, buf[0..], .{});
    defer data.deinit();

    for (data.value.vectors) |vector| {
        std.debug.print("buf = {s}\n", .{vector.protocol_name});

        break;
    }
}
