const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const print = std.debug.print;

const SymmetricState = @import("symmetric_state.zig").SymmetricState;

const KeyPair = @import("dh.zig").KeyPair;

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

pub fn keypairFromSecretKey(secret_key: []const u8) !KeyPair {
    var sk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sk, secret_key);
    const pk = try std.crypto.dh.X25519.recoverPublicKey(sk);

    return KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
        .public_key = pk,
        .secret_key = sk,
    } };
}

test "snow" {
    const allocator = std.testing.allocator;
    const snow_txt = try std.fs.cwd().openFile("./testdata/snow.txt", .{});
    const buf: []u8 = try snow_txt.readToEndAlloc(allocator, 1_000_000);
    defer std.testing.allocator.free(buf);

    // Validate snow.txt is loaded correctly
    try std.testing.expect(try std.json.validate(allocator, buf));
    const data = try std.json.parseFromSlice(Vectors, allocator, buf[0..], .{});
    defer data.deinit();

    // const wanted_patterns = [_][]const u8{ "N", "K", "X", "NN", "NK", "N1K", "NX", "KN", "KK", "KX", "IN", "IK", "IX", "XN", "XX", "XK" };
    // TODO: fix these patterns as well as add psk
    const wanted_patterns = [_][]const u8{ "KX1", "K1X1" };

    std.debug.print("Found {} total vectors\n", .{data.value.vectors.len});
    std.debug.print("\n\n", .{});
    var i: usize = 0;
    for (data.value.vectors) |vector| {
        const protocol = protocolFromName(vector.protocol_name);

        var should_test = true;
        for (wanted_patterns) |p| {
            if (std.mem.eql(u8, protocol.pattern, p)) {
                should_test = false;
            }
        }
        if (!should_test) continue;
        if (std.mem.eql(u8, protocol.dh, "448")) continue;
        std.debug.print("\n***** Testing: {s} *****\n", .{vector.protocol_name});

        const init_s = if (vector.init_static) |s| try keypairFromSecretKey(s) else null;
        const init_e = try keypairFromSecretKey(vector.init_ephemeral);

        var init_pk_rs: ?[32]u8 = undefined;
        if (vector.init_remote_static) |rs| {
            _ = try std.fmt.hexToBytes(&init_pk_rs.?, rs);
        }

        var init_prologue_buf: [100]u8 = undefined;
        const init_prologue = try std.fmt.hexToBytes(&init_prologue_buf, vector.init_prologue);

        var initiator = try HandshakeState.init(
            vector.protocol_name,
            allocator,
            try patternFromName(protocol.pattern),
            true,
            init_prologue,
            .{
                .s = init_s,
                .e = init_e,
                .rs = if (init_pk_rs) |rs| rs else null,
            },
        );
        defer initiator.deinit();

        const resp_s = if (vector.resp_static) |s| try keypairFromSecretKey(s) else null;
        const resp_e = try keypairFromSecretKey(vector.resp_ephemeral);

        var resp_pk_rs: ?[32]u8 = undefined;
        if (vector.resp_remote_static) |rs| {
            _ = try std.fmt.hexToBytes(&resp_pk_rs.?, rs);
        }
        var resp_prologue_buf: [100]u8 = undefined;
        const resp_prologue = try std.fmt.hexToBytes(&resp_prologue_buf, vector.resp_prologue);
        var responder = try HandshakeState.init(
            vector.protocol_name,
            allocator,
            try patternFromName(protocol.pattern),
            false,
            resp_prologue,
            .{
                .s = resp_s,
                .e = resp_e,
                .rs = if (resp_pk_rs) |rs| rs else null,
            },
        );
        defer responder.deinit();

        var send_buf = try ArrayList(u8).initCapacity(allocator, MAX_MESSAGE_LEN);
        var recv_buf = try ArrayList(u8).initCapacity(allocator, MAX_MESSAGE_LEN);
        defer send_buf.deinit();
        defer recv_buf.deinit();

        for (vector.messages, 0..) |m, j| {
            std.debug.print("\n***** Testing message {} *****\n", .{j});
            var sender = if (j % 2 == 0) &initiator else &responder;
            var receiver = if (j % 2 == 0) &responder else &initiator;
            std.debug.print("sender is initiator? {} \n", .{sender.is_initiator});

            var payload_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            const payload = try std.fmt.hexToBytes(&payload_buf, m.payload);
            _ = try sender.writeMessage(payload, &send_buf);

            var expected_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            var expected = try std.fmt.hexToBytes(&expected_buf, m.ciphertext);

            std.debug.print("Comparing send buf for message {}...\n", .{j});
            try std.testing.expectEqualSlices(u8, expected, send_buf.items);

            expected = try std.fmt.hexToBytes(&expected_buf, m.payload);
            _ = try receiver.readMessage(send_buf.items, &recv_buf);
            std.debug.print("Comparing recv buf for message {}...\n", .{j});
            try std.testing.expectEqualSlices(u8, expected, recv_buf.items);

            send_buf.clearAndFree();
            recv_buf.clearAndFree();
            std.debug.print("***** Message all good *****\n", .{});
        }

        i += 1;
        std.debug.print("***** Done with vector {} *****\n", .{i});
    }
}
