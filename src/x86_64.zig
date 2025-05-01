const std = @import("std");

const base = @import("base.zig");
const debug = base.debug;
const C = base.C;
const ContextPID = base.ContextPID;
const Perm = base.Perm;
// const read_cstr = base.read_cstr;

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
}

pub fn stat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("stat {s}, {}\n", .{ filename, regs.rsi });
}

pub fn lstat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("lstat {s}, {}\n", .{ filename, regs.rsi });
}

pub fn access(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("access {s}, {}\n", .{ filename, regs.rsi });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("={s}", .{dfd_path});

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try cpid.db.add(Perm.from_amode(@as(c_int, @intCast(regs.rsi))).?, path);
}

pub fn execve(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("execve {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    const dfd_path_buffer = try cpid.read_dfd_path(C.AT_FDCWD);
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("={s}", .{dfd_path});

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try cpid.db.add(.rx, path);
}

pub fn kill(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = cpid;
    debug.print("kill {}, {}\n", .{ regs.rdi, regs.rsi });
}

pub fn uname(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = cpid;
    debug.print("uname {}\n", .{regs.rdi});
}

pub fn truncate(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("truncate {s}, {}\n", .{ filename, regs.rsi });
}

pub fn chdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chdir {s}\n", .{filename});
}

pub fn rename(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("rename {s} {s}\n", .{ filename1, filename2 });
}

pub fn mkdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mkdir {s} {}\n", .{ filename, regs.rsi });
}

pub fn rmdir(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("rmdir {s}\n", .{filename});
}

pub fn creat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("creat {s} {}\n", .{ filename, regs.rsi });
}

pub fn link(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("link {s}, {s}\n", .{ filename1, filename2 });
}

pub fn unlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("unlink {s}\n", .{filename});
}

pub fn symlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("symlink {s}, {s}\n", .{ filename1, filename2 });
}

pub fn readlink(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("readlink {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
}

pub fn chmod(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chmod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
}

pub fn chown(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chown {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
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
}

pub fn utime(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utime {s}, {}\n", .{ filename, regs.rsi });
}

pub fn mknod(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mknod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });
}

pub fn statfs(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("statfs {s}, {}\n", .{ filename, regs.rsi });
}

pub fn chroot(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("chroot {s}\n", .{filename});
}

pub fn acct(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("acct {s}\n", .{filename});
}

pub fn mount(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rsi);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("mount {s}, {s}, {}, {}, {}\n", .{ filename1, filename2, regs.rdx, regs.r10, regs.r8 });
}

pub fn umount(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("umount {s}, {}\n", .{ filename, regs.rsi });
}

pub fn swapon(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("swapon {s}, {}\n", .{ filename, regs.rsi });
}

pub fn swapoff(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("swapoff {s}\n", .{filename});
}

pub fn utimes(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rdi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utimes {s}, {}\n", .{ filename, regs.rsi });
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

    debug.print("\tPath: {s}\n", .{path});

    const perm = Perm.from_mode(@intCast(regs.r10)).?;

    if (cpid.allow_all) {
        try cpid.db.add(perm, path);
        return;
    } else if (cpid.db.access(path).contains(.r)) {
        return;
    }

    // if (std.mem.eql(u8, path, "/home/konkito/Dev/zig/secure-run/message.txt")) {
    debug.print("Block\n", .{});

    regs.rax = std.math.maxInt(u64) - 4;
    regs.orig_rax = std.math.maxInt(u64);
    // }

    // try cpid.db.add(.r, path);
}

pub fn mkdirat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mkdirat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
}

pub fn mknodat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("mknodat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
}

pub fn fchownat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("fchownat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
}

pub fn futimesat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("futimesat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
}

pub fn newfstatat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("newfstatat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
}

pub fn unlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("unlinkat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
}

pub fn renameat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("renameat {}, {s}, {}, {s}\n", .{ regs.rdi, filename1, regs.rdx, filename2 });
}

pub fn linkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("linkat {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });
}

pub fn symlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rdi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.rdx);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("symlinkat {s}, {}, {s}\n", .{ filename1, regs.rsi, filename2 });
}

pub fn readlinkat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("readlinkat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
}

pub fn fchmodat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("fchmodat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
}

pub fn faccessat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("faccessat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });
}

pub fn utimensat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("utimensat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });
}

pub fn renameat2(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename1 = try cpid.read_filename(regs.rsi);
    const filename1 = std.mem.sliceTo(&_filename1, 0);
    const _filename2 = try cpid.read_filename(regs.r10);
    const filename2 = std.mem.sliceTo(&_filename2, 0);
    debug.print("renameat2 {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });
}

pub fn execveat(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("execvat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("={s}", .{dfd_path});

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try cpid.db.add(.rx, path);
}

pub fn statx(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    const _filename = try cpid.read_filename(regs.rsi);
    const filename = std.mem.sliceTo(&_filename, 0);
    debug.print("execvat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });
    const dfd_path_buffer = try cpid.read_dfd_path(@bitCast(@as(u32, @truncate(regs.rdi))));
    const dfd_path = std.mem.sliceTo(&dfd_path_buffer, 0);
    debug.print("={s}", .{dfd_path});

    const path = try std.fs.path.resolve(cpid.alloc, &.{ dfd_path, filename });
    defer cpid.alloc.free(path);

    try cpid.db.add(.f, path);
}
