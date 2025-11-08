//usr/bin/env zig run -lc "$0" -- "$@"; exit

const std = @import("std");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const env_map = try std.process.getEnvMap(alloc);

    const result_which = try std.process.Child.run(.{ .allocator = alloc, .env_map = &env_map, .argv = &.{ "/usr/bin/env", "which", "zig" } });
    const zig_path = std.mem.trim(u8, result_which.stdout, "\n");
    const zig_exe = try std.mem.concatWithSentinel(alloc, u8, &.{zig_path}, 0);
    std.debug.print("Zig Path: {s}\n", .{zig_exe});

    const dir_example = try std.fs.cwd().openDir("example/bin", .{ .iterate = true });
    var iterator = dir_example.iterate();

    const dir_build = try std.fs.cwd().makeOpenPath("example/build", .{});

    const progress = std.Progress.start(.{ .root_name = "build-examples", .estimated_total_items = 1 });

    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;

        std.debug.print("Building {s}\n", .{entry.name});

        const path = try dir_example.realpathAlloc(alloc, entry.name);
        const name = std.mem.trimEnd(u8, entry.name, ".c");

        if (std.mem.endsWith(u8, entry.name, ".c")) {
            const node = progress.start(name, 1);
            var child = std.process.Child.init(&.{ zig_path, "build-exe", "--name", name, "-lc", "-OReleaseSafe", path }, alloc);
            child.cwd_dir = dir_build;
            child.env_map = &env_map;
            child.progress_node = node;
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;
            const term = try child.spawnAndWait();
            if (term.Exited != 0) {
                std.debug.print("Failed to build: {s}", .{path});
                return;
            }
        }
    }

    progress.end();

    std.debug.print("All examples are built\n", .{});
}
