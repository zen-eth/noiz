//! A barebones TCP Server that establishes a `Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s` session, then listens and waits for a client to send a message before reading and decrypting it.
//!
//! To run, first `zig build`, and run the executable `zig-out/bin/oneway-server`.
//!
//! Adapted from: https://github.com/mcginty/snow/blob/main/examples/oneway.rs
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const noiz = @import("noiz");

const DH = noiz.DH;
const HandshakeState = noiz.handshake_state.HandshakeState;
const patternFromName = noiz.patternFromName;

const PSK: []const u8 = "A complicated enough system eventually becomes ensouled.";

/// Starts a server which listens for a oneway message.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const prologue = "";

    var responder_secret_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&responder_secret_key, "52fbe3721d1adbe312d270ca2db5ce5bd39ddc206075f3a8f06d422619c8eb5d");
    var responder_public_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&responder_public_key, "435ce8a8415ccd44de5e207581ac7207b416683028bcaecc9eb38d944e6f900c");

    const pattern = try patternFromName(
        allocator,
        "Xpsk1",
    );
    const responder_keypair = DH.KeyPair{ .inner = std.crypto.dh.X25519.KeyPair{
        .public_key = responder_public_key,
        .secret_key = responder_secret_key,
    } };

    var responder = try HandshakeState.init(
        "Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s",
        allocator,
        pattern,
        .Responder,
        prologue,
        PSK,
        .{
            .s = responder_keypair,
        },
    );

    const loopback = try std.net.Ip4Address.parse("127.0.0.1", 9999);
    const localhost = std.net.Address{ .in = loopback };
    var server = try localhost.listen(.{ .reuse_address = true });
    defer server.deinit();
    const addr = server.listen_address;
    std.debug.print("Listening on {}, access this port to end the program\n", .{addr.getPort()});
    var client = try server.accept();
    defer client.stream.close();

    var buf: [65535]u8 = undefined;
    const buf_len = try client.stream.readAll(&buf);

    var payload_buf = try ArrayList(u8).initCapacity(allocator, 65535);
    defer payload_buf.deinit();

    const read = buf[0..buf_len];
    _ = try responder.readMessage(read, &payload_buf);

    std.debug.print("Client said {s}\n", .{payload_buf.items});
}
