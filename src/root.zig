const handshake_pattern = @import("handshake_pattern.zig");

pub const handshake_state = @import("handshake_state.zig");
pub const patternFromName = handshake_pattern.patternFromName;
pub const Role = @import("handshake_state.zig").Role;
pub const Initiator = Role.Initiator;

test {
    _ = @import("cipher.zig");
    _ = @import("dh.zig");
    _ = @import("hash.zig");
    _ = @import("handshake_state.zig");
    _ = @import("symmetric_state.zig");
    _ = @import("cacophony_tests.zig");
}
