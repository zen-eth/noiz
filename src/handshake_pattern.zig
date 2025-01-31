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

pub const MessagePattern = []const MessageToken;

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
    /// N = **N**o static key for initiator
    /// N = **N**o static key for responder
    NN,
    /// N = **N**o static key for initiator
    /// K = Static key for responder **K**nown to initiator
    NK,
    /// N = **N**o static key for initiator
    /// K = Static key for responder **K**nown to initiator
    NK1,
    NX1,
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
    K1N,
    K1K,
    KK1,
    K1K1,
    K1X,
    KX1,
    K1X1,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// N = **N**o static key for responder
    XN,
    X1N,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// K = Static key for responder **K**nown to initiator
    XK,
    X1K,
    XK1,
    X1K1,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    XX,
    X1X,
    // XX1,
    XX1,
    X1X1,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IN,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// N = **N**o static key for responder
    IK,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IX,
    I1N,
    I1K,
    IK1,
    I1K1,
    I1X,
    IX1,
    I1X1,
};

pre_message_pattern_initiator: ?PreMessagePattern = null,
pre_message_pattern_responder: ?PreMessagePattern = null,
message_patterns: ArrayList(MessagePattern),

pub const HandshakePattern = @This();

pub fn patternFromName(allocator: Allocator, hs_pattern_name: []const u8) !HandshakePattern {
    const hs_pattern_name_en = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name);

    var modifier_it: std.mem.SplitIterator(u8, .any) = undefined;
    if (hs_pattern_name_en == null) {
        std.debug.print("name = {s}\n", .{hs_pattern_name});
        var modifier_str: []const u8 = undefined;
        for (1..hs_pattern_name.len) |i| {
            const foo = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name[0 .. hs_pattern_name.len - i]);
            std.debug.print("foo = {any}\n", .{foo});

            if (foo) |_| {
                modifier_str = hs_pattern_name[hs_pattern_name.len - i .. hs_pattern_name.len];
                break;
            }
        }
        std.debug.print("foo = {s}\n", .{modifier_str});
        modifier_it = std.mem.splitAny(u8, modifier_str, "+");
    }

    std.debug.print("pattern = {any}\n", .{hs_pattern_name_en});
    // _ = hs_pattern_name;
    // const hs_pattern_name_en: HandshakePatternName = .XXone;
    //
    var handshake_pattern: HandshakePattern = HandshakePattern{
        .message_patterns = ArrayList(MessagePattern).init(allocator),
    };

    switch (hs_pattern_name_en.?) {
        .N => {
            var patterns: [1]MessagePattern = .{&[_]MessageToken{ .e, .es }};
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .NN => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee },
            };
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .NK => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .es },
                &[_]MessageToken{ .e, .ee },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .NK1 => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .es },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .NX => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s, .es },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .NX1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s },
                &[_]MessageToken{.es},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },

        .K => {
            var patterns: [1]MessagePattern = .{&[_]MessageToken{ .e, .es, .ss }};
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .KN => {
            var patterns: [2]MessagePattern = [_]MessagePattern{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .se },
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .KK => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .es, .ss },
                &[_]MessageToken{ .e, .ee, .se },
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .KX => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .se, .s, .es },
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .K1N => {
            var patterns: [3]MessagePattern = [_]MessagePattern{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .K1K => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .es },
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .KK1 => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .se, .es },
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .K1K1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .es },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .K1X => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s, .es },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .KX1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .se, .s },
                &[_]MessageToken{.es},
            };
            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .K1X1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s },
                &[_]MessageToken{ .se, .es },
            };
            handshake_pattern.pre_message_pattern_initiator = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X => {
            var patterns: [1]MessagePattern = .{&[_]MessageToken{ .e, .es, .s, .ss }};
            try handshake_pattern.message_patterns.appendSlice(&patterns);
            handshake_pattern.pre_message_pattern_responder = .s;
        },
        .XN => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{ .s, .se },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X1N => {
            var patterns: [4]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.s},
                &[_]MessageToken{.se},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },

        .XK => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .es },
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{ .s, .se },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X1K => {
            var patterns: [4]MessagePattern = .{
                &[_]MessageToken{ .e, .es },
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.s},
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .XK1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .es },
                &[_]MessageToken{ .s, .se },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X1K1 => {
            var patterns: [4]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .es },
                &[_]MessageToken{.s},
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },

        .XX => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s, .es },
                &[_]MessageToken{ .s, .se },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X1X => {
            var patterns: [4]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s, .es },
                &[_]MessageToken{.s},
                &[_]MessageToken{.se},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .XX1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s },
                &[_]MessageToken{ .es, .s, .se },
            };
            std.debug.print("WHAT {any}\n", .{patterns});

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .X1X1 => {
            var patterns: [4]MessagePattern = .{
                &[_]MessageToken{.e},
                &[_]MessageToken{ .e, .ee, .s },
                &[_]MessageToken{ .es, .s },
                &[_]MessageToken{.se},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },

        .IN => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .se },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .I1N => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.se},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },

        .IK => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .es, .s, .ss },
                &[_]MessageToken{ .e, .ee, .se },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .I1K => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .es, .s },
                &[_]MessageToken{ .e, .ee },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .IK1 => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .se, .es },
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .I1K1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .es },
                &[_]MessageToken{.se},
            };

            handshake_pattern.pre_message_pattern_responder = .s;
            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .IX => {
            var patterns: [2]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .se, .s, .es },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .I1X => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .s, .es },
                &[_]MessageToken{.se},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .IX1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .se, .s },
                &[_]MessageToken{.es},
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
        .I1X1 => {
            var patterns: [3]MessagePattern = .{
                &[_]MessageToken{ .e, .s },
                &[_]MessageToken{ .e, .ee, .s },
                &[_]MessageToken{ .se, .es },
            };

            try handshake_pattern.message_patterns.appendSlice(&patterns);
        },
    }

    std.debug.print("hs pattern = {}\n", .{handshake_pattern});
    return handshake_pattern;
}

pub fn isOneWay(name: HandshakePatternName) bool {
    return switch (name) {
        .N, .X, .K => true,
        else => false,
    };
}
