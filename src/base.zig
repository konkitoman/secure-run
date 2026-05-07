const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const C = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/user.h");
    @cInclude("linux/ptrace.h");
    @cInclude("seccomp.h");
    @cInclude("limits.h");
    @cInclude("fcntl.h");
});

pub const DEBUG = true;

pub const debug = struct {
    pub fn print(comptime fmt: []const u8, args: anytype) void {
        if (DEBUG) std.debug.print(fmt, args);
    }
};

pub const Context = struct {
    db: DB,
    pctxs: std.AutoHashMap(C.__pid_t, ContextPID),
    allow_all: bool,
    allow_kill: bool,
    interactive: bool,
    stderr: *std.Io.Writer,
    stdin: *std.Io.Reader,
};

pub const ContextPID = struct {
    context: *Context,
    io: std.Io,
    alloc: Allocator,
    pid: C.pid_t,
    unimplemented: bool = false,

    pub fn read_filename(self: *@This(), from: usize) ![C.PATH_MAX]u8 {
        var buffer = std.mem.zeroes([C.PATH_MAX]u8);

        const len = std.os.linux.process_vm_readv(self.pid, &.{.{
            .base = (&buffer).ptr,
            .len = buffer.len,
        }}, &.{.{
            .base = @ptrFromInt(from),
            .len = 2097152, // value returned by, `getconf ARG_MAX`
        }}, 0);

        @memset(buffer[len..], 0);

        return buffer;
    }

    pub fn read_dfd_path(self: *@This(), dfd: c_int) ![std.fs.max_path_bytes]u8 {
        var buff: [std.fs.max_path_bytes]u8 = undefined;
        var buffer = std.Io.Writer.fixed(&buff);

        var output: [std.fs.max_path_bytes]u8 = undefined;
        if (dfd == C.AT_FDCWD) {
            try buffer.print("/proc/{}/cwd", .{self.pid});
        } else {
            try buffer.print("/proc/{}/fd/{}", .{ self.pid, dfd });
        }
        const path_len = try std.Io.Dir.readLinkAbsolute(self.io, buff[0..buffer.end], &output);
        @memset(output[path_len..], 0);

        return output;
    }

    pub fn _resume(self: *@This()) void {
        // if (self.file) |file| {
        //     file.close();
        //     self.file = null;
        // }

        _ = std.os.linux.ptrace(C.PTRACE_CONT, self.pid, 0, 0, 0);
    }
};

pub const Perm = enum(u5) {
    none = 0,
    f = 1,
    r = 2,
    fr = 3,
    w = 4,
    fw = 5,
    rw = 6,
    frw = 7,
    x = 8,
    fx = 9,
    rx = 10,
    frx = 11,
    wx = 12,
    fwx = 13,
    rwx = 14,
    frwx = 15,
    c = 16,
    fc = 17,
    rc = 18,
    frc = 19,
    wc = 20,
    fwc = 21,
    rwc = 22,
    frwc = 23,
    xc = 24,
    fxc = 25,
    rxc = 26,
    frxc = 27,
    wxc = 28,
    fwxc = 29,
    rwxc = 30,
    frwxc = 31,

    pub fn update(self: Perm, rhs: Perm) Perm {
        return @enumFromInt(@intFromEnum(self) | @intFromEnum(rhs));
    }

    pub fn contains(self: Perm, rhs: Perm) bool {
        const rhsi = @intFromEnum(rhs);
        return @intFromEnum(self) & rhsi == rhsi;
    }

    pub fn from_amode(int: c_int) ?Perm {
        return switch (int) {
            C.F_OK => .f,
            C.X_OK => .x,
            C.W_OK => .w,
            C.W_OK | C.X_OK => .wx,
            C.R_OK => .r,
            C.R_OK | C.X_OK => .rx,
            C.R_OK | C.W_OK => .rw,
            C.R_OK | C.W_OK | C.X_OK => .rwx,

            else => null,
        };
    }

    pub fn from_mode(int: c_int) Perm {
        var perm: Perm = .none;

        if (int & 3 == C.O_RDONLY) {
            perm = perm.update(.r);
        }
        if (int & 3 == C.O_WRONLY) {
            perm = perm.update(.w);
        }
        if (int & 3 == C.O_RDWR) {
            perm = perm.update(.rw);
        }

        if (int & C.O_CREAT == C.O_CREAT) {
            perm = perm.update(.c);
        }
        if (int & C.O_TRUNC == C.O_TRUNC) {
            perm = perm.update(.w);
        }

        return perm;
    }

    pub fn format(self: @This(), writer: *std.Io.Writer) !void {
        const e = @typeInfo(@This()).@"enum";
        inline for (e.fields) |field| {
            if (field.value == @intFromEnum(self)) return writer.print("{s}", .{field.name});
        }
    }
};

pub const Entry = struct {
    perm: Perm = .none,
    entries: std.array_hash_map.String(Entry),
    all: bool = false,
};

pub const DB = struct {
    alloc: Allocator,
    root: Entry,

    pub fn init(alloc: Allocator) !@This() {
        return .{ .alloc = alloc, .root = .{ .entries = try std.array_hash_map.String(Entry).init(alloc, &.{}, &.{}) } };
    }

    pub fn deinit(self: *@This()) !void {
        var stack: std.ArrayList(Entry) = .empty;
        defer stack.deinit(self.alloc);

        var to_deinit: std.ArrayList(Entry) = .empty;
        defer to_deinit.deinit(self.alloc);

        try stack.append(self.alloc, self.root);

        while (stack.items.len != 0) {
            const a = stack.pop().?;
            try to_deinit.append(self.alloc, a);

            for (a.entries.keys()) |key| {
                self.alloc.free(key);
            }

            try stack.appendSlice(self.alloc, a.entries.values());
        }

        for (to_deinit.items) |*v| {
            v.entries.deinit(self.alloc);
        }
    }

    pub fn add(self: *@This(), perm: Perm, data: []const u8) !void {
        assert(data.len != 0);
        assert(data[0] == '/');

        var d = data[1..];

        var entry = &self.root;

        while (true) {
            const len = if (std.mem.indexOf(u8, d, "/")) |pos| pos else d.len;

            if (len == 0 and d.len > 0) {
                d = d[1..];
                continue;
            }

            if (d.len != 0) {
                if (!entry.entries.contains(d[0..len])) {
                    if (std.mem.eql(u8, d[0..len], "*")) {
                        entry.all = true;
                    } else {
                        const key = try self.alloc.alloc(u8, len);
                        @memcpy(key, d[0..len]);
                        try entry.entries.put(
                            self.alloc,
                            key,
                            .{ .perm = .none, .all = false, .entries = try std.StringArrayHashMapUnmanaged(Entry).init(self.alloc, &.{}, &.{}) },
                        );
                    }
                }

                if (entry.entries.getPtr(d[0..len])) |value| {
                    entry = value;
                }
            }

            if (d.len > len) {
                d = d[len + 1 ..];
                continue;
            }
            break;
        }

        entry.perm = entry.perm.update(perm);
    }

    pub fn access(self: @This(), path: []const u8) Perm {
        assert(path.len != 0);
        assert(path[0] == '/');

        var perm = Perm.none;

        var d = path[1..];

        var entry = self.root;

        while (d.len != 0) {
            const len = if (std.mem.indexOf(u8, d, "/")) |pos| pos else d.len;

            if (len == 0 and d.len != 0) {
                d = d[1..];
                continue;
            }

            const e = entry;

            if (e.all) {
                perm = e.perm;
            }

            if (e.entries.get(d[0..len])) |v| {
                entry = v;
            } else {
                return perm;
            }

            if (d.len > len) {
                d = d[len + 1 ..];
                continue;
            }
            break;
        }

        if (d.len == 0) {
            return entry.perm;
        } else {
            return entry.perm.update(perm);
        }
    }

    pub const Path = struct {
        Perm,
        []const u8,
    };

    pub fn getPaths(self: @This()) ![]const Path {
        var paths: std.ArrayList(Path) = .empty;

        const E = struct {
            path: std.ArrayList(u8),
            entry: Entry,
        };

        var entries: std.ArrayList(E) = .empty;
        defer entries.deinit(self.alloc);

        try entries.append(self.alloc, .{ .path = .empty, .entry = self.root });

        while (entries.items.len != 0) {
            const _entries = try self.alloc.alloc(E, entries.items.len);
            defer self.alloc.free(_entries);
            @memcpy(_entries, entries.items);
            entries.clearRetainingCapacity();

            for (_entries) |*e| {
                defer e.path.deinit(self.alloc);
                if (e.entry.all) {
                    const _path = try self.alloc.alloc(u8, e.path.items.len + 2);
                    @memcpy(_path[0..e.path.items.len], e.path.items);
                    @memcpy(_path[e.path.items.len..], "/*");
                    try paths.append(self.alloc, .{ e.entry.perm, _path });
                } else {
                    if (e.entry.perm != .none) {
                        if (e.path.items.len == 0) {
                            const _path = try self.alloc.alloc(u8, 1);
                            @memcpy(_path, "/");
                            try paths.append(self.alloc, .{ e.entry.perm, _path });
                        } else {
                            const _path = try self.alloc.alloc(u8, e.path.items.len);
                            @memcpy(_path, e.path.items);
                            try paths.append(self.alloc, .{ e.entry.perm, _path });
                        }
                    }
                }

                for (e.entry.entries.keys()) |key| {
                    var path = try e.path.clone(self.alloc);
                    try path.append(self.alloc, '/');
                    try path.appendSlice(self.alloc, key);
                    try entries.append(self.alloc, .{ .path = path, .entry = e.entry.entries.get(key).? });
                }
            }
        }

        paths.shrinkAndFree(self.alloc, paths.items.len);

        return paths.items;
    }

    pub fn freePaths(self: @This(), paths: []const Path) void {
        for (paths) |path| {
            self.alloc.free(path.@"1");
        }
        self.alloc.free(paths);
    }
};

fn test_paths(db: *DB) !void {
    try std.testing.expectEqual(db.access("/"), .f);
    try std.testing.expectEqual(db.access("/a//b"), .fr);
    try std.testing.expectEqual(db.access("/a/b"), .fr);
    try std.testing.expectEqual(db.access("/a/c/b"), .frw);
}

test "DB_access" {
    var db = try DB.init(std.testing.allocator);
    defer db.deinit() catch {};
    try db.add(.f, "/");
    try db.add(.fr, "/a//b");
    try db.add(.frw, "/a/c/b");

    try test_paths(&db);

    const paths = try db.getPaths();

    var new_db = try DB.init(std.testing.allocator);
    defer new_db.deinit() catch {};
    for (paths) |path| {
        try new_db.add(path.@"0", path.@"1");
    }

    db.freePaths(paths);

    try test_paths(&new_db);
}

pub fn read_cstr_len(mem: std.fs.File, start: usize) !usize {
    var i: usize = 0;
    var buffer: [1]u8 = undefined;
    try mem.seekTo(start);
    while (true) {
        _ = try mem.read(&buffer);
        if (buffer[0] == 0) {
            break;
        }
        if (i >= C.ARG_MAX) {
            return error.CannotDeterminCstrlen;
        }
        i += 1;
    }

    return i;
}

pub fn read_cstr(alloc: Allocator, mem: std.fs.File, start: usize) ![]u8 {
    const len = try read_cstr_len(mem, start);
    const buffer = try alloc.alloc(u8, len);
    errdefer alloc.free(buffer);
    _ = try mem.preadAll(buffer, start);
    return buffer;
}

pub fn read(mem: std.fs.File, buffer: []u8, start: usize) !void {
    _ = try mem.preadAll(buffer, start);
}

/// This function is like a series of `cd` statements executed one after another.
/// It resolves "." and "..", but will not convert relative path to absolute path, use std.fs.Dir.realpath instead.
/// The result does not have a trailing path separator.
/// This function does not perform any syscalls. Executing this series of path
/// lookups on the actual filesystem may produce different results due to
/// symlinks.
pub fn resolveZ(allocator: Allocator, paths: []const []const u8) Allocator.Error![:0]u8 {
    assert(paths.len > 0);

    var result = std.array_list.Managed(u8).init(allocator);
    defer result.deinit();

    var negative_count: usize = 0;
    var is_abs = false;

    for (paths) |p| {
        if (std.fs.path.isAbsolutePosix(p)) {
            is_abs = true;
            negative_count = 0;
            result.clearRetainingCapacity();
        }
        var it = std.mem.tokenizeScalar(u8, p, '/');
        while (it.next()) |component| {
            if (std.mem.eql(u8, component, ".")) {
                continue;
            } else if (std.mem.eql(u8, component, "..")) {
                if (result.items.len == 0) {
                    negative_count += @intFromBool(!is_abs);
                    continue;
                }
                while (true) {
                    const ends_with_slash = result.items[result.items.len - 1] == '/';
                    result.items.len -= 1;
                    if (ends_with_slash or result.items.len == 0) break;
                }
            } else if (result.items.len > 0 or is_abs) {
                try result.ensureUnusedCapacity(1 + component.len);
                result.appendAssumeCapacity('/');
                result.appendSliceAssumeCapacity(component);
            } else {
                try result.appendSlice(component);
            }
        }
    }

    if (result.items.len == 0) {
        if (is_abs) {
            return allocator.dupeZ(u8, "/\x00");
        }
        if (negative_count == 0) {
            return allocator.dupeZ(u8, ".\x00");
        } else {
            const real_result = try allocator.allocSentinel(u8, 3 * negative_count - 1, 0);
            var count = negative_count - 1;
            var i: usize = 0;
            while (count > 0) : (count -= 1) {
                real_result[i..][0..3].* = "../".*;
                i += 3;
            }
            real_result[i..][0..2].* = "..".*;
            return real_result;
        }
    }

    try result.append(0);

    if (negative_count == 0) {
        return result.toOwnedSliceSentinel(0);
    } else {
        const real_result = try allocator.allocSentinel(u8, 3 * negative_count + result.items.len, 0);
        var count = negative_count;
        var i: usize = 0;
        while (count > 0) : (count -= 1) {
            real_result[i..][0..3].* = "../".*;
            i += 3;
        }
        @memcpy(real_result[i..][0..result.items.len], result.items);
        return real_result;
    }
}
