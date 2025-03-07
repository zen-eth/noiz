const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;

pub const MessageToken = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
};

const PreMessagePattern = enum {
    e,
    s,
    es,
    empty,
};

/// The following handshake patterns represent interactive protocols. These 12 patterns are called the fundamental interactive handshake patterns.
// The fundamental interactive patterns are named with two characters, which indicate the status of the initiator and responder's static keys. The first and second characters refer to the initiator's and responder's static key respectively.
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
message_patterns: MessagePatternArray,

pub const MessagePatternArray = struct {
    buffer: []MessageToken,
    pattern_lens: []usize,
    pattern_index: usize = 0,
    token_index: usize = 0,

    pub fn fromTokens(allocator: Allocator, token_arrs: []const BoundedTokenArray) !MessagePatternArray {
        var pattern_lens = try allocator.alloc(usize, token_arrs.len);
        var num_tokens: usize = 0;

        for (token_arrs, 0..) |a, i| {
            num_tokens += a.len;
            pattern_lens[i] = a.len;
        }

        var buffer = try allocator.alloc(MessageToken, num_tokens);

        var i: usize = 0;
        for (token_arrs) |a| {
            for (a.constSlice(), 0..) |t, j| {
                buffer[i + j] = t;
            }
            i += a.len;
        }

        return .{
            .buffer = buffer,
            .pattern_lens = pattern_lens,
        };
    }

    pub fn next(self: *MessagePatternArray) ?[]const MessageToken {
        if (self.isFinished()) return null;

        const len = self.pattern_lens[self.pattern_index];
        const slice = self.buffer[self.token_index .. self.token_index + len];
        self.pattern_index += 1;
        self.token_index += len;

        return slice;
    }

    pub fn isFinished(self: *MessagePatternArray) bool {
        return self.pattern_index >= self.pattern_lens.len;
    }

    pub fn deinit(self: *MessagePatternArray, allocator: Allocator) void {
        allocator.free(self.buffer);
        allocator.free(self.pattern_lens);
    }
};

pub const HandshakePattern = @This();

// Protocol names are always in the format "Noise_..." and are limited to <= 255 bytes.
//
// Given the shortest possible base protocol name: "Noise_N_448_AESGCM_SHA256" (25 bytes)
// We have 255 - 25 = 230 bytes to spare.
//
// The shortest modifier is 'pskX' (4 bytes), where 'X' is an integer specifying where to insert a psk token.
// These modifiers are separated by '+' (1 byte).
// (230 - 4) = 226 / 5 = 45 modifiers
//
// We can have roughly 45 modifiers within a protocol name in the worst case, but realistically this wouldn't be the case (we wouldn't append 'psk0' multiple times for example).
//
// Perhaps we can safely estimate it to be 45 modifiers / 4 maximum patterns = ~11 modifiers per pattern, and we add it to the known maximum number of tokens in a pattern which is 4, so 11 + 4 = 15 tokens. This is probably not even important, why did i bother calculating this?
const BoundedTokenArray = BoundedArray(MessageToken, 15);

pub fn patternFromName(allocator: Allocator, hs_pattern_name: []const u8) !HandshakePattern {
    var hs_pattern_name_en = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name);

    var modifier_it: std.mem.SplitIterator(u8, .any) = undefined;
    if (hs_pattern_name_en == null) {
        var modifier_str: []const u8 = undefined;
        for (1..hs_pattern_name.len) |i| {
            const pattern = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name[0 .. hs_pattern_name.len - i]);

            if (pattern) |_| {
                modifier_str = hs_pattern_name[hs_pattern_name.len - i .. hs_pattern_name.len];
                hs_pattern_name_en = pattern;
                break;
            }
        }
        modifier_it = std.mem.splitAny(u8, modifier_str, "+");
    }

    var handshake_pattern: HandshakePattern = HandshakePattern{
        .message_patterns = undefined,
    };

    var message_patterns = try BoundedArray(BoundedTokenArray, 4).init(0);

    switch (hs_pattern_name_en.?) {
        .N => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append((try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es })));
        },
        .NN => {
            try message_patterns.append((try BoundedTokenArray.fromSlice(&[_]MessageToken{.e})));
            try message_patterns.append((try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee })));
        },
        .NK => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append((try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es })));
            try message_patterns.append((try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee })));
        },
        .NK1 => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .es }));
        },
        .NX => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s, .es }));
        },
        .NX1 => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.es}));
        },

        .K => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es, .ss }));
        },
        .KN => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se }));
        },
        .KK => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es, .ss }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se }));
        },
        .KX => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .s, .es }));
        },
        .K1N => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .K1K => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .KK1 => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .es }));
        },
        .K1K1 => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .K1X => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .KX1 => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.es}));
        },
        .K1X1 => {
            handshake_pattern.pre_message_pattern_initiator = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .se, .es }));
        },
        .X => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es, .s, .ss }));
        },
        .XN => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .s, .se }));
        },
        .X1N => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.s}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },

        .XK => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .s, .se }));
        },
        .X1K => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.s}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .XK1 => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .s, .se }));
        },
        .X1K1 => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.s}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },

        .XX => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .s, .se }));
        },
        .X1X => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.s}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .XX1 => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .es, .s, .se }));
        },
        .X1X1 => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.e}));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .es, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .IN => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se }));
        },
        .I1N => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },

        .IK => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es, .s, .ss }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se }));
        },
        .I1K => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .es, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .IK1 => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .es }));
        },
        .I1K1 => {
            handshake_pattern.pre_message_pattern_responder = .s;
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .IX => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .s, .es }));
        },
        .I1X => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s, .es }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.se}));
        },
        .IX1 => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .se, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{.es}));
        },
        .I1X1 => {
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .e, .ee, .s }));
            try message_patterns.append(try BoundedTokenArray.fromSlice(&[_]MessageToken{ .se, .es }));
        },
    }

    while (modifier_it.next()) |m| {
        if (std.mem.containsAtLeast(u8, m, 1, "psk")) {
            const num = try std.fmt.parseInt(usize, m["psk".len .. "psk".len + 1], 10);

            if (num == 0) {
                try message_patterns.slice()[0].insert(0, .psk);
            } else {
                try message_patterns.slice()[num - 1].append(.psk);
            }
        }
    }

    const patterns = try MessagePatternArray.fromTokens(allocator, message_patterns.constSlice());
    handshake_pattern.message_patterns = patterns;

    return handshake_pattern;
}

pub fn isOneWay(name: HandshakePatternName) bool {
    return switch (name) {
        .N, .X, .K => true,
        else => false,
    };
}
