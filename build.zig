const std = @import("std");
const Translator = @import("translate_c").Translator;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const translate_c = b.dependency("translate_c", .{});
    const translator: Translator = .init(translate_c, .{
        .c_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_system_libs = &.{},
    });
    const module = b.addModule("secure-run", .{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .link_libc = true, .imports = &.{.{ .name = "c", .module = translator.mod }} });

    module.linkSystemLibrary("seccomp", .{ .needed = true });

    const exe = b.addExecutable(.{
        .name = "secure-run",
        .root_module = module,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const base_unit_module = b.createModule(.{
        .root_source_file = b.path("src/base.zig"),
        .target = target,
    });

    const base_unit_tests = b.addTest(.{
        .root_module = base_unit_module,
    });

    const exe_unit_tests = b.addTest(.{
        .root_module = module,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const run_base_unit_tests = b.addRunArtifact(base_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
    test_step.dependOn(&run_base_unit_tests.step);
}
