const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const noiz = @import("noiz");
const DH = @import("../../src/dh.zig").DH;

const HandshakeState = noiz.handshake_state.HandshakeState;
const patternFromName = noiz.patternFromName;
const Role = noiz.Role;

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

    const pattern = try patternFromName(
        allocator,
        "Xpsk1",
    );
    var initiator = try HandshakeState.init(
        "Noise_Xpsk1_25519_ChaChaPoly_BLAKE2s",
        allocator,
        pattern,
        .Initiator,
        prologue,
        PSK,
        .{
            .s = initiator_keypair,
            .rs = responder_public_key,
        },
    );
    defer initiator.deinit();

    const loopback = try std.net.Ip4Address.parse("127.0.0.1", 9999);
    const localhost = std.net.Address{ .in = loopback };
    var server = try localhost.listen(.{ .reuse_address = true });
    defer server.deinit();
    const addr = server.listen_address;
    std.debug.print("Listening on {}, access this port to end the program\n", .{addr.getPort()});
    var client = try server.accept();
    defer client.stream.close();
}
