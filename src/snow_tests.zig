const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SymmetricState = @import("symmetric_state.zig").SymmetricState;
const protocolFromName = @import("symmetric_state.zig").protocolFromName;
const HandshakeState = @import("handshake_state.zig").HandshakeState;
const patternFromName = @import("handshake_pattern.zig").patternFromName;
const MAX_MESSAGE_LEN = @import("handshake_state.zig").MAX_MESSAGE_LEN;
const HandshakePatternName = @import("handshake_pattern.zig").HandshakePatternName;
const HandshakePattern = @import("handshake_pattern.zig").HandshakePattern;
const MessagePattern = @import("handshake_pattern.zig").MessagePattern;

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
    const snow_txt = try std.fs.cwd().openFile("./testdata/snow2.txt", .{});
    const buf: []u8 = try snow_txt.readToEndAlloc(std.testing.allocator, 1_000_000);
    defer std.testing.allocator.free(buf);

    // Validate snow.txt is loaded correctly
    try std.testing.expect(try std.json.validate(std.testing.allocator, buf));
    const data = try std.json.parseFromSlice(Vectors, std.testing.allocator, buf[0..], .{});
    defer data.deinit();

    for (data.value.vectors) |vector| {
        const protocol = protocolFromName(vector.protocol_name);

        if (std.mem.eql(u8, protocol.dh, "448")) continue;

        const init_s = blk: {
            if (vector.init_static) |s| {
                var sk_s: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(&sk_s, s);
                const pub_static = try std.crypto.dh.X25519.recoverPublicKey(sk_s);

                break :blk DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
                    .public_key = pub_static,
                    .secret_key = sk_s,
                } };
            } else break :blk null;
        };

        var init_sk_e: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&init_sk_e, vector.init_ephemeral);
        const init_pub_ephemeral = try std.crypto.dh.X25519.recoverPublicKey(init_sk_e);

        const init_e = DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
            .public_key = init_pub_ephemeral,
            .secret_key = init_sk_e,
        } };

        var init_sk_rs: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&init_sk_rs, vector.init_remote_static.?);

        var prologue: [100]u8 = undefined;
        const decoded = try std.fmt.hexToBytes(&prologue, vector.init_prologue);

        var initiator = try HandshakeState.init(
            vector.protocol_name,
            allocator,
            std.meta.stringToEnum(HandshakePatternName, protocol.pattern).?,
            try patternFromName(std.testing.allocator, protocol.pattern),
            true,
            decoded,
            .{
                .s = init_s,
                .e = init_e,
                .rs = init_sk_rs,
                .re = null,
            },
        );
        defer initiator.deinit();

        const resp_s = blk: {
            if (vector.resp_static) |s| {
                var sk_s: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(&sk_s, s);
                const pub_static = try std.crypto.dh.X25519.recoverPublicKey(sk_s);

                break :blk DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
                    .public_key = pub_static,
                    .secret_key = sk_s,
                } };
            } else break :blk null;
        };

        var resp_sk_e: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&resp_sk_e, vector.resp_ephemeral);
        const resp_pub_ephemeral = try std.crypto.dh.X25519.recoverPublicKey(resp_sk_e);
        const resp_e = DH().KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
            .public_key = resp_pub_ephemeral,
            .secret_key = resp_sk_e,
        } };

        var resp_rs_sk: [32]u8 = undefined;
        if (vector.resp_remote_static) |rs| {
            _ = try std.fmt.hexToBytes(&resp_rs_sk, rs);
        }
        const resp_rs = try std.crypto.dh.X25519.recoverPublicKey(resp_rs_sk);

        var responder = try HandshakeState.init(
            vector.protocol_name,
            allocator,
            std.meta.stringToEnum(HandshakePatternName, protocol.pattern).?,
            try patternFromName(std.testing.allocator, protocol.pattern),
            false,
            vector.resp_prologue,
            .{
                .s = resp_s,
                .e = resp_e,
                .rs = resp_rs,
                .re = null,
            },
        );
        defer responder.deinit();

        var send_buf = try ArrayList(u8).initCapacity(std.testing.allocator, MAX_MESSAGE_LEN);
        defer send_buf.deinit();
        // var recv_buf: [MAX_MESSAGE_LEN]u8 = undefined;

        for (vector.messages, 0..) |m, i| {
            var sender = if (i % 2 == 0) initiator else responder;
            const receiver = if (i % 2 == 0) responder else initiator;
            _ = receiver;

            var payload_buf = [_]u8{0} ** MAX_MESSAGE_LEN;
            const payload = try std.fmt.hexToBytes(&payload_buf, m.payload);
            _ = try sender.writeMessage(payload, &send_buf);

            var expected_buf: [200]u8 = undefined;
            const expected = try std.fmt.hexToBytes(&expected_buf, m.ciphertext);
            try std.testing.expectEqualSlices(u8, expected, send_buf.items);
        }

        break;
    }
}
