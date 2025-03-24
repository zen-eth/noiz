const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "noiz",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.addModule("noiz", .{
        .root_source_file = b.path("src/root.zig"),
    });

    b.installArtifact(lib);

    const enable_logging = b.option(bool, "log", "Whether to enable logging") orelse false;

    const options = b.addOptions();
    options.addOption(bool, "enable_logging", enable_logging);

    const filters = b.option([]const []const u8, "filter", "filter based on name");

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .filters = filters orelse &.{},
    });
    lib_unit_tests.root_module.addImport("options", options.createModule());

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
