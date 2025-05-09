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

pub const ContextPID = struct {
    alloc: Allocator,
    pid: C.pid_t,
    pids: *std.ArrayListUnmanaged(C.pid_t),
    file: ?std.fs.File = null,
    unimplemented: bool = false,
    db: *DB,
    allow_all: bool,
    allow_kill: bool,
    interactive: bool,

    pub fn mem(self: *@This()) std.fs.File {
        if (self.file) |file| {
            return file;
        } else {
            var buffer = std.ArrayListUnmanaged(u8){};
            defer buffer.deinit(self.alloc);
            std.fmt.format(buffer.writer(self.alloc), "/proc/{}/mem", .{self.pid}) catch |err| {
                std.debug.panic("Cannot format: {}\n", .{err});
            };
            if (std.fs.openFileAbsolute(buffer.items, .{ .mode = .read_write })) |file| {
                self.file = file;
                return file;
            } else |err| {
                std.debug.panic("Cannot open mem file: {}\n", .{err});
            }
        }
    }

    pub fn read_filename(self: *@This(), from: usize) ![C.PATH_MAX]u8 {
        var buffer = std.mem.zeroes([C.PATH_MAX]u8);

        const len = std.os.linux.process_vm_readv(self.pid, &.{.{
            .base = (&buffer).ptr,
            .len = buffer.len,
        }}, &.{.{
            .base = @ptrFromInt(from),
            .len = C.ARG_MAX,
        }}, 0);

        @memset(buffer[len..], 0);

        return buffer;
    }

    pub fn read_dfd_path(self: *@This(), dfd: c_int) ![std.fs.max_path_bytes]u8 {
        var buffer = try std.BoundedArray(u8, std.fs.max_path_bytes).init(0);
        var output: [std.fs.max_path_bytes]u8 = undefined;
        if (dfd == C.AT_FDCWD) {
            try buffer.writer().print("/proc/{}/cwd", .{self.pid});
        } else {
            try buffer.writer().print("/proc/{}/fd/{}", .{ self.pid, dfd });
        }
        const path = try std.fs.readLinkAbsolute(buffer.slice(), &output);
        @memset(output[path.len..], 0);

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

pub const Perm = enum(u4) {
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
            C.X_OK => .fx,
            C.W_OK => .fw,
            C.W_OK | C.X_OK => .fwx,
            C.R_OK => .fr,
            C.R_OK | C.X_OK => .frx,
            C.R_OK | C.W_OK => .frw,
            C.R_OK | C.W_OK | C.X_OK => .frwx,

            else => null,
        };
    }

    pub fn from_mode(int: c_int) ?Perm {
        if (int & 3 == C.O_RDONLY) return .fr;
        if (int & 3 == C.O_WRONLY) return .fw;
        if (int & 3 == C.O_RDWR) return .frw;

        return null;
    }

    pub fn format(self: @This(), fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        const e = @typeInfo(@This()).@"enum";
        inline for (e.fields) |field| {
            if (field.value == @intFromEnum(self)) return writer.print("{s}", .{field.name});
        }
    }
};

pub const Entry = struct {
    perm: Perm = .none,
    entries: std.StringArrayHashMapUnmanaged(Entry),
    all: bool = false,
};

pub const DB = struct {
    alloc: Allocator,
    root: Entry,

    pub fn init(alloc: Allocator) !@This() {
        return .{ .alloc = alloc, .root = .{ .entries = try std.StringArrayHashMapUnmanaged(Entry).init(alloc, &.{}, &.{}) } };
    }

    pub fn deinit(self: *@This()) !void {
        var stack = std.ArrayListUnmanaged(Entry){};
        defer stack.deinit(self.alloc);

        var to_deinit = std.ArrayListUnmanaged(Entry){};
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
            const e = entry;

            if (e.all) {
                perm = e.perm;
            }

            if (e.entries.get(d[0..len])) |v| {
                entry = v;
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
        perm: Perm,
        path: []const u8,
    };

    pub fn getPaths(self: @This()) ![]const Path {
        var paths = std.ArrayListUnmanaged(Path){};

        const E = struct {
            path: std.ArrayListUnmanaged(u8),
            entry: Entry,
        };

        var entries = std.ArrayListUnmanaged(E){};
        defer entries.deinit(self.alloc);

        try entries.append(self.alloc, .{ .path = .{}, .entry = self.root });

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
                    try paths.append(self.alloc, .{ .perm = e.entry.perm, .path = _path });
                } else {
                    if (e.entry.perm != .none) {
                        const _path = try self.alloc.alloc(u8, e.path.items.len);
                        @memcpy(_path, e.path.items);
                        try paths.append(self.alloc, .{ .perm = e.entry.perm, .path = _path });
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
            self.alloc.free(path.path);
        }
        self.alloc.free(paths);
    }
};

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
