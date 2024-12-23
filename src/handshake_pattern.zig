const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const MessageToken = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
};

pub const MessagePattern = []MessageToken;

const PreMessagePattern = enum {
    e,
    s,
    es,
    empty,
};

/// The following handshake patterns represent interactive protocols. These 12 patterns are called the fundamental interactive handshake patterns.
/// The fundamental interactive patterns are named with two characters, which indicate the status of the initiator and responder's static keys. The first and second characters refer to the initiator's and responder's static key respectively.
pub const HandshakePatternName = enum {
    /// N = **N**o static key for recipient
    N,
    /// K = Static key for sender **K**nown to recipient
    K,
    /// X = Static key for sender **X**mitted (transmitted) to recipient
    X,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    I,
    /// N = **N**o static key for initiator
    /// N = **N**o static key for responder
    NN,
    /// N = **N**o static key for initiator
    /// K = Static key for responder **K**nown to initiator
    NK,
    /// N = **N**o static key for initiator
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    NX,
    /// K = Static key for initiator **K**nown to responder
    /// N = **N**o static key for responder
    KN,
    /// K = Static key for initiator **K**nown to responder
    /// K = Static key for responder **K**nown to initiator
    KK,
    /// K = Static key for initiator **K**nown to responder
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    KX,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// N = **N**o static key for responder
    XN,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// K = Static key for responder **K**nown to initiator
    XK,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    XX,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IN,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// N = **N**o static key for responder
    IK,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IX,
};

pre_message_pattern_initiator: ?PreMessagePattern,
pre_message_pattern_responder: ?PreMessagePattern,
message_patterns: []MessagePattern,

pub const HandshakePattern = @This();

pub fn patternFromName(allocator: Allocator, hs_pattern_name: []const u8) !HandshakePattern {
    const hs_pattern_name_en = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name).?;
    switch (hs_pattern_name_en) {
        .N => {
            const tokens: []MessageToken = try allocator.alloc(MessageToken, 2);
            errdefer allocator.free(tokens);
            var patterns: []MessagePattern = try allocator.alloc(MessagePattern, 1);
            errdefer allocator.free(patterns);

            std.mem.copyForwards(MessageToken, tokens, &[_]MessageToken{ .e, .es });
            @memset(patterns[0..1], tokens);

            return .{
                .pre_message_pattern_initiator = null,
                .pre_message_pattern_responder = .s,
                .message_patterns = patterns,
            };
        },
        .NN => {
            const tokens: []MessageToken = try allocator.alloc(MessageToken, 2);
            errdefer allocator.free(tokens);
            var patterns: []MessagePattern = try allocator.alloc(MessagePattern, 2);
            errdefer allocator.free(patterns);

            std.mem.copyForwards(MessageToken, tokens, &[_]MessageToken{
                .e,
            });
            @memset(patterns[0..1], tokens);
            const tokens2: []MessageToken = try allocator.alloc(MessageToken, 2);
            std.mem.copyForwards(MessageToken, tokens2, &[_]MessageToken{ .e, .ee });
            @memset(patterns[1..2], tokens2);

            return .{
                .pre_message_pattern_initiator = null,
                .pre_message_pattern_responder = null,
                .message_patterns = patterns,
            };
        },

        // .K => {
        //     return .{
        //         .pre_message_pattern_initiator = .s,
        //         .pre_message_pattern_responder = .s,
        //         .message_patterns = .{ .e, .es, .ss },
        //     };
        // },
        .X => {
            const tokens: []MessageToken = try allocator.alloc(MessageToken, 4);
            errdefer allocator.free(tokens);
            var patterns: []MessagePattern = try allocator.alloc(MessagePattern, 1);
            errdefer allocator.free(patterns);

            std.mem.copyForwards(MessageToken, tokens, &[_]MessageToken{ .e, .es, .s, .ss });
            @memset(patterns[0..1], tokens);

            return .{
                .pre_message_pattern_initiator = null,
                .pre_message_pattern_responder = .s,
                .message_patterns = patterns,
            };
        },
        else => {
            @panic("unimpl");
        },
    }
}

pub fn isOneWay(name: HandshakePatternName) bool {
    return switch (name) {
        .N, .X, .K => true,
        else => false,
    };
}
