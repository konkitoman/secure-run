const std = @import("std");

const base = @import("base.zig");
const debug = base.debug;
const C = base.C;
const ContextPID = base.ContextPID;
const Perm = base.Perm;

pub fn _deny(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = regs;

    cpid.unimplemented = true;
}

pub fn _allow(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = cpid;
    _ = regs;
}

pub fn open(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("open {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    const perm = Perm.from_mode(@bitCast(@as(u32, @truncate(regs.rdx)))).?;

    try file_interaction(cpid, regs, perm, path);
}

pub fn stat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("stat {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .f, path);
}

pub fn lstat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("lstat {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .f, path);
}

pub fn access(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("access {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    const perm = Perm.from_amode(@bitCast(@as(u32, @truncate(regs.rsi)))).?;

    try file_interaction(cpid, regs, perm, path);
}

pub fn execve(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("execve {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .frx, path);
}

pub fn kill(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const pid: C.pid_t = @bitCast(@as(u32, @truncate(regs.rdi)));
    debug.print("{}: kill {}, {}\n", .{ cpid.pid, pid, regs.rsi });
    if (std.mem.indexOfAny(C.pid_t, cpid.pids.items, &.{pid})) |_| return;
    if (cpid.allow_kill) return;

    if (cpid.interactive) {
        try std.io.getStdErr().writer().print("Allow to send kill {} to {} [y/N]: ", .{ regs.rsi, pid });
        const input = try std.io.getStdIn().reader().readUntilDelimiterAlloc(cpid.alloc, '\n', std.math.maxInt(usize));
        defer cpid.alloc.free(input);

        if (std.mem.eql(u8, input, "y") or std.mem.eql(u8, input, "Y")) return;
    }

    regs.rax = std.math.maxInt(u64);
    regs.orig_rax = std.math.maxInt(u64);
}

pub fn truncate(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("truncate {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn chdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chdir {s}\n", .{filename});
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .f, path);
}

pub fn rename(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("rename {s} {s}\n", .{ filename1, filename2 });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .frw, path1);
    try file_interaction(cpid, regs, .fw, path2);
}

pub fn mkdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mkdir {s} {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    const i = std.mem.lastIndexOf(u8, path, "/").?;
    debug.print("Parent: {s}\n", .{path[0..i]});
    try file_interaction(cpid, regs, .w, path[0..i]);
}

pub fn rmdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("rmdir {s}\n", .{filename});

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn creat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("creat {s} {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn link(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("link {s}, {s}\n", .{ filename1, filename2 });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .f, path1);
    try file_interaction(cpid, regs, .f, path2);
}

pub fn unlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("unlink {s}\n", .{filename});

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn symlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("symlink {s}, {s}\n", .{ filename1, filename2 });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .f, path1);
    try file_interaction(cpid, regs, .f, path2);
}

pub fn readlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("readlink {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fr, path);
}

pub fn chmod(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chmod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn chown(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chown {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn ptrace(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = cpid;

    debug.print("ptrace {}, {}, {}, {}\n", .{ regs.rdi, regs.rsi, regs.rdx, regs.r10 });

    // anti debugger detection.
    if (regs.rdi == C.PTRACE_TRACEME) {
        regs.rax = 1;
        regs.orig_rax = std.math.maxInt(u64);
    }
    if (regs.rdi == C.PTRACE_DETACH) {
        regs.rax = 0;
        regs.orig_rax = std.math.maxInt(u64);
    }
}

pub fn lchown(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("lchown {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn utime(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utime {s}, {}\n", .{ filename, regs.rsi });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn mknod(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mknod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn statfs(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("statfs {s}, {}\n", .{ filename, regs.rsi });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn chroot(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chroot {s}\n", .{filename});
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .frw, path);
}

pub fn acct(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    if (regs.rdi == 0) return;

    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("acct {s}\n", .{filename});
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn mount(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("mount {s}, {s}, {}, {}, {}\n", .{ filename1, filename2, regs.rdx, regs.r10, regs.r8 });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .f, path1);
    try file_interaction(cpid, regs, .f, path2);
}

pub fn umount(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("umount {s}, {}\n", .{ filename, regs.rsi });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn swapon(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("swapon {s}, {}\n", .{ filename, regs.rsi });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .frw, path);
}

pub fn swapoff(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("swapoff {s}\n", .{filename});
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn utimes(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utimes {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn openat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const dfd: c_int = @bitCast(@as(c_uint, @truncate(regs.rdi)));
    debug.print("openat {}", .{dfd});
    const dfd_path_buffer = try cpid.read_dfd_path(dfd);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("={s}", .{dfd_path});
    const filename_buffer = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&filename_buffer, 0);
    debug.print(", {s}, {}, {}\n", .{ filename, regs.rdx, regs.r10 });

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);
    const perm = Perm.from_mode(@intCast(regs.r10)).?;
    try file_interaction(cpid, regs, perm, path);
}

pub fn mkdirat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const dfd: c_int = @bitCast(@as(c_uint, @truncate(regs.rdi)));
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    const dfd_path_buffer = try cpid.read_dfd_path(dfd);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("mkdirat {}={s}, {s}, {}\n", .{ regs.rdi, dfd_path, filename, regs.rdx });
    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    const i = std.mem.lastIndexOf(u8, path, "/").?;
    debug.print("Parent: {s}\n", .{path[0..i]});
    try file_interaction(cpid, regs, .w, path[0..i]);
}

pub fn mknodat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mknodat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn fchownat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("fchownat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn futimesat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("futimesat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn newfstatat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("newfstatat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .f, path);
}

pub fn unlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("unlinkat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn renameat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("renameat {}, {s}, {}, {s}\n", .{ regs.rdi, filename1, regs.rdx, filename2 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .frw, path1);
    try file_interaction(cpid, regs, .fw, path1);
}

pub fn linkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("linkat {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .f, path1);
    try file_interaction(cpid, regs, .f, path1);
}

pub fn symlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rdx);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("symlinkat {s}, {}, {s}\n", .{ filename1, regs.rsi, filename2 });
    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    const o_dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rsi))));
    const o_dfd_path = std.mem.sliceTo(&o_dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ o_dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .f, path1);
    try file_interaction(cpid, regs, .f, path1);
}

pub fn readlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("readlinkat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fr, path);
}

pub fn fchmodat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("fchmodat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn faccessat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("faccessat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, Perm.from_amode(@bitCast(@as(u32, @truncate(regs.rdx)))).?, path);
}

pub fn utimensat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utimensat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .fw, path);
}

pub fn renameat2(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("renameat2 {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const i_dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    const o_dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdx))));
    const o_dfd_path = std.mem.sliceTo(&o_dfd_path_buffer, 0);

    const path1 = try std.fs.path.resolve(cpid.alloc, &.{ i_dfd_path, filename1 });
    defer cpid.alloc.free(path1);
    const path2 = try std.fs.path.resolve(cpid.alloc, &.{ o_dfd_path, filename2 });
    defer cpid.alloc.free(path2);

    try file_interaction(cpid, regs, .frw, path1);
    try file_interaction(cpid, regs, .fw, path1);
}

pub fn execveat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("execvat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .frx, path);
}

pub fn statx(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    var _filename = std.mem.zeroes([C.PATH_MAX]u8);
    if (regs.rsi != 0) {
        _filename = try cpid.read_filename(regs.rsi);
    }
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("statx {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try file_interaction(cpid, regs, .f, path);
}

fn file_interaction(cpid: *ContextPID, regs: *C.struct_user_regs_struct, perm: Perm, path: []const u8) !void {
    if (cpid.allow_all) {
        if (!cpid.db.access(path).contains(perm)) try cpid.db.add(perm, path);
        return;
    } else if (cpid.db.access(path).contains(perm)) {
        return;
    }

    if (cpid.interactive) {
        try std.io.getStdErr().writer().print("Add permissions {} to {s} [y/N]:", .{ perm, path });
        const input = try std.io.getStdIn().reader().readUntilDelimiterAlloc(cpid.alloc, '\n', std.math.maxInt(usize));
        defer cpid.alloc.free(input);
        if (std.mem.eql(u8, input, "y") or std.mem.eql(u8, input, "Y")) {
            try cpid.db.add(perm, path);
            return;
        }
    }

    regs.rax = std.math.maxInt(u64) - 4;
    regs.orig_rax = std.math.maxInt(u64);
}
