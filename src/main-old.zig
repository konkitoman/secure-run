const std = @import("std");
const debug = std.debug;
const linux = std.os.linux;
const c = std.c;

const C = @cImport({
    @cInclude("sys/user.h");
    @cInclude("linux/ptrace.h");
    @cInclude("seccomp.h");
    @cInclude("limits.h");
});

const Allocator = std.mem.Allocator;

pub fn run(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) i32 {
    const r = c.fork();

    if (r == 0) {
        _ = linux.ptrace(linux.PTRACE.TRACEME, 0, 0, 0, 0);
        _ = c.raise(c.SIG.STOP);

        // const ctx = C.seccomp_init(C.SCMP_ACT_TRACE(1));
        // debug.print("CTX: {*}\n", .{ctx});
        // const res = C.seccomp_load(ctx);
        // debug.print("RES: {}\n", .{res});

        const ret = c.execve(path, argv, envp);
        debug.panic("Returnet from execve {}", .{ret});
    }

    return r;
}

pub const ContextPID = struct {
    next: usize,
    mem: std.fs.File,
};

fn sys_nothing(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    _ = alloc;
    _ = cpid;
    _ = regs;
    return false;
}

fn sys_open(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("open {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_stat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("stat {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_lstat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("lstat {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_access(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("access {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_execve(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("execve {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_kill(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    _ = alloc;
    _ = cpid;
    std.debug.print("kill {}, {}\n", .{ regs.rdi, regs.rsi });
    return false;
}

fn sys_uname(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    _ = alloc;
    _ = cpid;
    std.debug.print("uname {}\n", .{regs.rdi});
    return false;
}

fn sys_truncate(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("truncate {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_chdir(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("chdir {s}\n", .{filename});

    return false;
}

fn sys_rename(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename2);
    std.debug.print("rename {s} {s}\n", .{ filename1, filename2 });

    return false;
}

fn sys_mkdir(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("mkdir {s} {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_rmdir(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("rmdir {s}\n", .{filename});

    return false;
}

fn sys_creat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("creat {s} {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_link(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename2);
    std.debug.print("link {s}, {s}\n", .{ filename1, filename2 });

    return false;
}

fn sys_unlink(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("unlink {s}\n", .{filename});

    return false;
}

fn sys_symlink(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename2);
    std.debug.print("symlink {s}, {s}\n", .{ filename1, filename2 });

    return false;
}

fn sys_readlink(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("readlink {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_chmod(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("chmod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_chown(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("chown {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_lchown(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("lchown {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_utime(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("utime {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_mknod(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("mknod {s}, {}, {}\n", .{ filename, regs.rsi, regs.rdx });

    return false;
}

fn sys_statfs(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("statfs {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_chroot(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("chroot {s}\n", .{filename});

    return false;
}

fn sys_acct(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("acct {s}\n", .{filename});

    return false;
}

fn sys_mount(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename2);
    std.debug.print("mount {s}, {s}, {}, {}, {}\n", .{ filename1, filename2, regs.rdx, regs.r10, regs.r8 });

    return false;
}

fn sys_umount(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("umount {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_swapon(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("swapon {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_swapoff(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("swapoff {s}\n", .{filename});

    return false;
}

fn sys_utimes(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename);
    std.debug.print("utimes {s}, {}\n", .{ filename, regs.rsi });

    return false;
}

fn sys_openat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("openat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });

    return false;
}

fn sys_mkdirat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("mkdirat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });

    return false;
}

fn sys_mknodat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("mknodat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });

    return false;
}

fn sys_fchownat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("fchownat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });

    return false;
}

fn sys_futimesat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("futimesat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });

    return false;
}

fn sys_newfstatat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("newfstatat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });

    return false;
}

fn sys_unlinkat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("unlinkat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });

    return false;
}

fn sys_renameat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.r10);
    defer alloc.free(filename2);
    std.debug.print("renameat {}, {s}, {}, {s}\n", .{ regs.rdi, filename1, regs.rdx, filename2 });

    return false;
}

fn sys_linkat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.r10);
    defer alloc.free(filename2);
    std.debug.print("linkat {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });

    return false;
}

fn sys_symlinkat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rdi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.rdx);
    defer alloc.free(filename2);
    std.debug.print("symlinkat {s}, {}, {s}\n", .{ filename1, regs.rsi, filename2 });

    return false;
}

fn sys_readlinkat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("readlinkat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });

    return false;
}

fn sys_fchmodat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("fchmodat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });

    return false;
}

fn sys_faccessat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("faccessat {}, {s}, {}\n", .{ regs.rdi, filename, regs.rdx });

    return false;
}

fn sys_utimensat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("utimensat {}, {s}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10 });

    return false;
}

fn sys_renameat2(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename1 = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename1);
    const filename2 = try read_cstr(alloc, cpid.mem, regs.r10);
    defer alloc.free(filename2);
    std.debug.print("renameat2 {}, {s}, {}, {s}, {}\n", .{ regs.rdi, filename1, regs.rdx, filename2, regs.r8 });

    return false;
}

fn sys_execveat(alloc: Allocator, cpid: *ContextPID, regs: *C.struct_user_regs_struct) !bool {
    const filename = try read_cstr(alloc, cpid.mem, regs.rsi);
    defer alloc.free(filename);
    std.debug.print("utimensat {}, {s}, {}, {}, {}\n", .{ regs.rdi, filename, regs.rdx, regs.r10, regs.r8 });

    return false;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var process_args = std.ArrayListUnmanaged(?[*:0]const u8){};
    defer process_args.deinit(alloc);
    var read_args = false;

    var args = std.process.args();
    while (args.next()) |arg| {
        if (read_args) {
            try process_args.append(alloc, arg);

            continue;
        }

        if (std.mem.eql(u8, arg, "--")) {
            read_args = true;
        }
    }

    try process_args.append(alloc, null);

    var pid = run(@ptrCast(process_args.items[0]), @ptrCast(process_args.items), std.c.environ);

    var context = std.AutoHashMap(C.__pid_t, ContextPID).init(alloc);
    defer context.deinit();

    var status: c.siginfo_t = undefined;
    _ = c.waitpid(pid, @ptrCast(&status), 0);
    debug.print("Status: {}\n", .{status});

    _ = linux.ptrace(C.PTRACE_SEIZE, pid, 0, 0, 0);
    _ = linux.ptrace(C.PTRACE_SETOPTIONS, pid, 0, C.PTRACE_O_EXITKILL | C.PTRACE_O_TRACECLONE | C.PTRACE_O_TRACEFORK | C.PTRACE_O_TRACEVFORK, 0);
    _ = linux.ptrace(C.PTRACE_SYSEMU, pid, 0, 0, 0);

    var path_to_mem = std.ArrayList(u8).init(gpa.allocator());
    defer path_to_mem.deinit();

    {
        path_to_mem.clearRetainingCapacity();
        try std.fmt.format(path_to_mem.writer(), "/proc/{}/mem", .{pid});
        const mem = try std.fs.openFileAbsolute(path_to_mem.items, .{ .mode = .read_write });
        try context.put(pid, ContextPID{ .next = 0, .mem = mem });
    }

    debug.print("Child: {}\n", .{pid});

    var syscalls: [457]*const fn (Allocator, *ContextPID, *C.struct_user_regs_struct) anyerror!bool = undefined;
    @memset(&syscalls, sys_nothing);

    syscalls[2] = sys_open;
    syscalls[4] = sys_stat;
    syscalls[6] = sys_lstat;
    syscalls[21] = sys_access;
    syscalls[59] = sys_execve;
    syscalls[62] = sys_kill;
    syscalls[63] = sys_uname;
    syscalls[76] = sys_truncate;
    syscalls[80] = sys_chdir;
    syscalls[82] = sys_rename;
    syscalls[83] = sys_mkdir;
    syscalls[84] = sys_rmdir;
    syscalls[85] = sys_creat;
    syscalls[86] = sys_link;
    syscalls[87] = sys_unlink;
    syscalls[88] = sys_symlink;
    syscalls[89] = sys_readlink;
    syscalls[90] = sys_chmod;
    syscalls[92] = sys_chown;
    syscalls[94] = sys_lchown;
    syscalls[132] = sys_utime;
    syscalls[133] = sys_mknod;
    syscalls[137] = sys_statfs;
    syscalls[161] = sys_chroot;
    syscalls[163] = sys_acct;
    syscalls[165] = sys_mount;
    syscalls[166] = sys_umount;
    syscalls[167] = sys_swapon;
    syscalls[168] = sys_swapoff;
    syscalls[235] = sys_utimes;
    syscalls[257] = sys_openat;
    syscalls[258] = sys_mkdirat;
    syscalls[259] = sys_mknodat;
    syscalls[260] = sys_fchownat;
    syscalls[261] = sys_futimesat;
    syscalls[262] = sys_newfstatat;
    syscalls[263] = sys_unlinkat;
    syscalls[264] = sys_renameat;
    syscalls[265] = sys_linkat;
    syscalls[266] = sys_symlinkat;
    syscalls[267] = sys_readlinkat;
    syscalls[268] = sys_fchmodat;
    syscalls[269] = sys_faccessat;
    syscalls[280] = sys_utimensat;
    syscalls[316] = sys_renameat2;
    syscalls[322] = sys_execveat;

    while (true) {
        debug.print("\n", .{});
        var skip = false;

        pid = c.waitpid(-1, @ptrCast(&status), 0);

        var trap = false;
        var siginfo = std.mem.zeroes(c.siginfo_t);
        _ = linux.ptrace(C.PTRACE_GETSIGINFO, pid, 0, @intFromPtr(&siginfo), 0);
        debug.print("siginfo: {} {} {}\n", .{ siginfo.signo, siginfo.code, siginfo.errno });

        debug.print("{}: {} Status: ", .{ pid, status.signo });
        switch ((status.signo >> 8) & 0xff) {
            c.SIG.TRAP => {
                debug.print("SIGTRAP ", .{});
                switch (status.signo >> 16) {
                    0 => debug.print("\n", .{}),
                    C.PTRACE_EVENT_FORK => {
                        debug.print("Fork\n", .{});
                    },
                    C.PTRACE_EVENT_VFORK => {
                        debug.print("VFork\n", .{});
                    },
                    C.PTRACE_EVENT_CLONE => {
                        debug.print("Clone\n", .{});
                    },
                    C.PTRACE_EVENT_EXEC => {
                        debug.print("Exec\n", .{});
                    },
                    C.PTRACE_EVENT_EXIT => {
                        debug.print("Exit\n", .{});
                    },
                    C.PTRACE_EVENT_STOP => {
                        debug.print("STOP\n", .{});
                    },
                    else => {
                        debug.print("Unknown {}\n", .{status.signo >> 16});
                    },
                }
                trap = true;
            },
            c.SIG.SEGV => {
                _ = linux.ptrace(C.PTRACE_INTERRUPT, pid, 0, 0, 0);
                continue;
            },
            c.SIG.STOP => {
                debug.print("SIGSTOP: {}\n", .{status.signo >> 16});
                _ = linux.ptrace(linux.PTRACE.SEIZE, pid, 0, 0, 0);
                _ = linux.ptrace(linux.PTRACE.SETOPTIONS, pid, 0, C.PTRACE_O_EXITKILL | C.PTRACE_O_TRACECLONE | C.PTRACE_O_TRACEFORK | C.PTRACE_O_TRACEVFORK, 0);
                _ = linux.ptrace(C.PTRACE_SYSEMU, pid, 0, 0, 0);

                path_to_mem.clearRetainingCapacity();
                try std.fmt.format(path_to_mem.writer(), "/proc/{}/mem", .{pid});
                const mem = try std.fs.openFileAbsolute(path_to_mem.items, .{ .mode = .read_write });

                try context.put(pid, ContextPID{ .next = 0, .mem = mem });
                continue;
            },
            0 => {},
            else => {
                debug.print("Unknown {}\n", .{status.signo >> 8});
            },
        }

        if (pid == -1) {
            debug.print("Process exited!\n", .{});
            break;
        }

        var regs: C.struct_user_regs_struct = undefined;
        _ = linux.ptrace(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs), 0);
        debug.print("RIP: 0x{x}\n", .{regs.rip});

        if (!trap) {
            _ = linux.ptrace(C.PTRACE_SYSEMU, pid, 0, 0, 0);
            continue;
        }

        const pcontext = context.getPtr(pid).?;

        {
            pcontext.mem.close();
            path_to_mem.clearRetainingCapacity();
            try std.fmt.format(path_to_mem.writer(), "/proc/{}/mem", .{pid});
            pcontext.mem = try std.fs.openFileAbsolute(path_to_mem.items, .{ .mode = .read_write });
        }

        if (pcontext.next != 0) {
            _ = linux.ptrace(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs), 0);
            if (pcontext.next == 1) {
                _ = linux.ptrace(C.PTRACE_SYSEMU, pid, 0, 0, 0);
            } else {
                _ = linux.ptrace(C.PTRACE_SINGLESTEP, pid, 0, 0, 0);
            }
            pcontext.next -= 1;
            continue;
        }

        skip = false;

        if (regs.orig_rax <= 456) {
            skip = try syscalls[regs.orig_rax](alloc, pcontext, &regs);
        } else {
            debug.panic("Unknown syscall {}", .{regs.orig_rax});
        }

        if (skip) {
            _ = linux.ptrace(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs), 0);
            _ = linux.ptrace(C.PTRACE_SYSEMU, pid, 0, 0, 0);
        } else {
            regs.rip -= 2; // x86 syscall is 2 bytes
            regs.rax = regs.orig_rax;
            pcontext.next = 2;
            _ = linux.ptrace(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs), 0);
            _ = linux.ptrace(C.PTRACE_SINGLESTEP, pid, 0, 0, 0);
        }
    }
}

fn read_cstr_len(mem: std.fs.File, start: usize) !usize {
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

fn read_cstr(alloc: Allocator, mem: std.fs.File, start: usize) ![]u8 {
    const len = try read_cstr_len(mem, start);
    const buffer = try alloc.alloc(u8, len);
    errdefer alloc.free(buffer);
    _ = try mem.preadAll(buffer, start);
    return buffer;
}

fn read(mem: std.fs.File, buffer: []u8, start: usize) !void {
    _ = try mem.preadAll(buffer, start);
}
