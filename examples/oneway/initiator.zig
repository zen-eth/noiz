//! A barebones TCP Client that establishes a `Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s` session, and sends
//! an important message across the wire.
//!
//! To run, first `zig build`, and run the executable `zig-out/bin/oneway-initiator`.
//!
//! Adapted from: https://github.com/mcginty/snow/blob/main/examples/oneway.rs
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const noiz = @import("noiz");
const HandshakeState = noiz.handshake_state.HandshakeState;
const DH = noiz.DH;
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

    const initiator_keypair = try DH.KeyPair.generate(null);

    var initiator = try HandshakeState.initName(
        "Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s",
        allocator,
        .Initiator,
        prologue,
        PSK,
        .{
            .s = initiator_keypair,
            .rs = responder_public_key,
        },
    );

    const server = try std.net.Address.parseIp("127.0.0.1", 9999);
    const stream = try std.net.tcpConnectToAddress(server);
    defer stream.close();

    std.debug.print("Connecting to {}\n", .{server});

    var buf = try ArrayList(u8).initCapacity(allocator, 65535);
    defer buf.deinit();

    const data = "hello zig";
    _ = try initiator.writeMessage(data, &buf);
    // Sending data to peer
    var writer = stream.writer();
    const size = try writer.write(buf.items);
    std.debug.print("Sending '{s}' to peer, total written: {d} bytes\n", .{ data, size });
}
