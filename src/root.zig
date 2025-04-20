const handshake_pattern = @import("handshake_pattern.zig");

pub const handshake_state = @import("handshake_state.zig");
pub const patternFromName = handshake_pattern.patternFromName;
pub const DH = @import("dh.zig").DH;

///The max message length in bytes.
///
///See: http://www.noiseprotocol.org/noise.html#message-format
pub const MAX_MESSAGE_LEN = 65535;
pub const cipher = @import("cipher.zig");
pub const hash   = @import("hash.zig");
pub const symmetric_state = @import("symmetric_state.zig");

test {
    _ = @import("cipher.zig");
    _ = @import("dh.zig");
    _ = @import("hash.zig");
    _ = @import("handshake_state.zig");
    _ = @import("symmetric_state.zig");
    _ = @import("cacophony_tests.zig");
}
