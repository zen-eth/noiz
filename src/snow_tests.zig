const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const SymmetricState2 = @import("symmetric_state.zig").SymmetricState2;
const protocolFromName = @import("symmetric_state.zig").protocolFromName;
const HandshakeState = @import("handshake_state.zig").HandshakeState;
const HandshakePatternName = @import("handshake_state.zig").HandshakePatternName;
const HandshakePattern = @import("handshake_state.zig").HandshakePattern;
const MessagePattern = @import("handshake_state.zig").MessagePattern;
const MessageToken = @import("handshake_state.zig").MessageToken;
const CipherStateChaCha = @import("cipher.zig").CipherStateChaCha;

const HashSha256 = @import("hash.zig").HashSha256;
const HashSha512 = @import("hash.zig").HashSha512;
const HashBlake2b = @import("hash.zig").HashBlake2b;
const HashBlake2s = @import("hash.zig").HashBlake2s;
const HashChoice = @import("hash.zig").HashChoice;

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
const CipherChoice = @import("./cipher.zig").CipherChoice;
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
    const allocator = std.testing.allocator;
    const snow_txt = try std.fs.cwd().openFile("./testdata/snow.txt", .{});
    const buf: []u8 = try snow_txt.readToEndAlloc(std.testing.allocator, 1_000_000);
    defer std.testing.allocator.free(buf);

    // Validate snow.txt is loaded correctly
    try std.testing.expect(try std.json.validate(std.testing.allocator, buf));
    const data = try std.json.parseFromSlice(Vectors, std.testing.allocator, buf[0..], .{});
    defer data.deinit();

    var i: usize = 0;
    for (data.value.vectors) |vector| {
        const protocol = protocolFromName(vector.protocol_name);
        std.debug.print("{s} {s} {any} {any}\n", .{ protocol.pattern, protocol.dh, protocol.cipher, protocol.hash });

        const s = blk: {
            if (vector.init_static) |init_s| {
                var sk_s: [32]u8 = undefined;
                @memcpy(&sk_s, init_s);
                const pub_static = try std.crypto.dh.X25519.recoverPublicKey(sk_s);

                break :blk DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
                    .public_key = pub_static,
                    .secret_key = sk_s,
                } };
            } else break :blk null;
        };

        var sk_e: [32]u8 = undefined;
        @memcpy(&sk_e, vector.init_ephemeral[0..32]);
        const pub_ephemeral = try std.crypto.dh.X25519.recoverPublicKey(sk_e);

        const e = DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
            .public_key = pub_ephemeral,
            .secret_key = sk_e,
        } };

        var rs: [32]u8 = undefined;
        @memcpy(&rs, vector.init_remote_static.?[0..32]);

        var re: [32]u8 = undefined;
        @memcpy(&re, vector.resp_ephemeral[0..32]);
        // const initiator = SymmetricState2.init(allocator, vector.protocol_name);
        const pattern = &[_]MessageToken{.e};
        var msg_patterns = [_]MessagePattern{pattern};

        std.debug.print("vec: {s}\n", .{vector.protocol_name});
        const initiator = HandshakeState.init(
            vector.protocol_name,
            allocator,
            std.meta.stringToEnum(HandshakePatternName, protocol.pattern).?,
            HandshakePattern{
                .pre_message_pattern_initiator = null,
                .pre_message_pattern_responder = null,
                .message_patterns = &msg_patterns,
            },
            true,
            vector.init_prologue,
            s,
            e,
            rs,
            re,
        );

        std.debug.print("{any}", .{initiator});
        i += 1;

        if (i == 5) break;
    }
}
