const std = @import("std");
const builtin = @import("builtin");
// const debug = std.debug;
const linux = std.os.linux;
const c = std.c;

const base = @import("base.zig");
const debug = base.debug;
const C = base.C;
const ContextPID = base.ContextPID;
const DB = base.DB;

const Allocator = std.mem.Allocator;

const sys = if (builtin.target.cpu.arch.isX86()) @import("x86_64.zig") else @panic("Not implemented for this platform!");

pub fn run(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) C.pid_t {
    const r = c.fork();

    if (r == 0) {
        _ = linux.ptrace(linux.PTRACE.TRACEME, 0, 0, 0, 0);
        _ = c.raise(c.SIG.STOP);

        const ctx = C.seccomp_init(C.SCMP_ACT_TRACE(1));
        const res = C.seccomp_load(ctx);
        _ = res;

        _ = c.execve(path, argv, envp);
        std.process.abort();
    }

    return r;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var process_args = std.ArrayListUnmanaged(?[*:0]const u8){};
    defer process_args.deinit(alloc);
    var read_args = false;

    var allow_all = false;
    var save = false;
    var interactive = false;
    var network = false;
    var allow_unknown_syscalls = false;
    var allow_kill = false;

    var args = std.process.args();
    while (args.next()) |arg| {
        if (read_args) {
            try process_args.append(alloc, arg);

            continue;
        }

        if (std.mem.eql(u8, arg, "--")) {
            read_args = true;
            continue;
        }

        if (std.mem.startsWith(u8, arg, "-")) {
            for (arg[1..]) |ch| switch (ch) {
                'a' => allow_all = true,
                's' => save = true,
                'i' => interactive = true,
                'n' => network = true,
                'u' => allow_unknown_syscalls = true,
                'k' => allow_kill = true,
                'h' => {
                    var stdio = std.io.getStdIn();
                    const w = stdio.writer();
                    try w.print("Showing the help:\n", .{});
                    try w.print("-a Allow all\n", .{});
                    try w.print("-s Save on exit, in permissions.zon in the current directory\n", .{});
                    try w.print("-i Interactive mode, when a program tries to access a file and has not permissions will ask\n", .{});
                    try w.print("-n Allow network syscalls, socket, bind, listen, accept\n", .{});
                    try w.print("-u Allow unknown syscalls\n", .{});
                    try w.print("-k Allow kill\n", .{});
                    std.process.exit(0);
                },
                else => {
                    debug.print("Invalid arg: -{c}\n", .{ch});
                },
            };
        }
    }

    if (!read_args) {
        std.debug.print("Not program specified\n", .{});
        std.process.exit(1);
    }

    var cwd_path_buffer = std.mem.zeroes([std.fs.max_path_bytes]u8);
    const cwd_path = try std.fs.readLinkAbsolute("/proc/self/cwd", &cwd_path_buffer);

    var pids = std.ArrayListUnmanaged(C.pid_t){};
    defer pids.deinit(alloc);

    try process_args.append(alloc, null);

    const exe_path = try std.fs.path.resolve(alloc, &.{ cwd_path, std.mem.sliceTo(process_args.items[0].?, 0) });
    defer alloc.free(exe_path);

    if (c.access(@ptrCast(exe_path), c.F_OK) != 0) {
        std.debug.print("secure-run: no such file: {s}\n", .{exe_path});
        std.process.exit(1);
    }

    var db = try DB.init(alloc);
    try db.add(.frx, exe_path);
    try db.add(.fr, "/usr/lib/libc.so.6");

    var pid = run(@ptrCast(exe_path), @ptrCast(process_args.items), std.c.environ);
    // const main_pid = pid;
    debug.print("MAIN PID: {}\n", .{pid});

    var context = std.AutoHashMap(C.__pid_t, ContextPID).init(alloc);
    defer context.deinit();

    const file_path = "permissions.zon";
    debug.print("Opening: {s}\n", .{file_path});
    if (std.fs.cwd().openFile(file_path, .{})) |file| {
        defer file.close();
        const data = try file.readToEndAlloc(alloc, std.math.maxInt(usize));
        var status = std.zon.parse.Status{};
        defer status.deinit(alloc);
        const paths = try std.zon.parse.fromSlice([]const base.DB.Path, alloc, @ptrCast(data), &status, .{});
        debug.print("Status: {}\n", .{status});

        for (paths) |path| {
            try db.add(path.perm, path.path);
        }

        std.zon.parse.free(alloc, paths);
        alloc.free(data);
    } else |err| {
        debug.print("Cannot open: {s} {}\n", .{ file_path, err });
    }

    var syscalls: [457]*const fn (*ContextPID, *C.struct_user_regs_struct) anyerror!void = undefined;
    @memset(&syscalls, if (allow_unknown_syscalls) sys._allow else sys._deny);

    syscalls[0] = sys._allow; // read
    syscalls[1] = sys._allow; // write
    syscalls[2] = sys.open;
    syscalls[3] = sys._allow; // close
    syscalls[4] = sys.stat;
    syscalls[5] = sys._allow; // fstat
    syscalls[6] = sys.lstat;
    syscalls[7] = sys._allow; // pool
    syscalls[8] = sys._allow; // lseek
    syscalls[9] = sys._allow; // mmap
    syscalls[10] = sys._allow; // mprotect
    syscalls[11] = sys._allow; // munmap
    syscalls[12] = sys._allow; // brk
    syscalls[13] = sys._allow; // rt_sigaction
    syscalls[14] = sys._allow; // rt_sigprocmask
    syscalls[15] = sys._allow; // rt_sigreturn
    syscalls[16] = sys._allow; // ioctl
    syscalls[17] = sys._allow; // pread64
    syscalls[18] = sys._allow; // pwrite64
    syscalls[21] = sys.access;
    syscalls[22] = sys._allow; // pipe
    syscalls[23] = sys._allow; // select
    syscalls[24] = sys._allow; // sched_yield
    syscalls[25] = sys._allow; // mremap
    syscalls[26] = sys._allow; // msync
    syscalls[27] = sys._allow; // mincore
    syscalls[28] = sys._allow; // madvise
    syscalls[29] = sys._allow; // shmget
    syscalls[30] = sys._allow; // shmat
    syscalls[31] = sys._allow; // shmctl
    syscalls[32] = sys._allow; // dup
    syscalls[33] = sys._allow; // dup2
    syscalls[34] = sys._allow; // pause
    syscalls[35] = sys._allow; // nanosleep
    syscalls[36] = sys._allow; // getitimer
    syscalls[37] = sys._allow; // alarm
    syscalls[38] = sys._allow; // setitimer
    syscalls[39] = sys._allow; // getpid
    syscalls[40] = sys._allow; // sendfile
    syscalls[41] = if (network) sys._allow else sys._deny; // socket
    syscalls[42] = if (network) sys._allow else sys._deny; // connect
    syscalls[43] = if (network) sys._allow else sys._deny; // accept
    syscalls[44] = sys._allow; // sendto
    syscalls[45] = sys._allow; // recvfrom
    syscalls[46] = sys._allow; // sendmsg
    syscalls[47] = sys._allow; // recvmsg
    syscalls[48] = sys._allow; // shutdown
    syscalls[49] = if (network) sys._allow else sys._deny; // bind
    syscalls[50] = if (network) sys._allow else sys._deny; // listen
    syscalls[51] = sys._allow; // getsockname
    syscalls[52] = sys._allow; // getpeername
    syscalls[53] = sys._allow; // socketpair
    syscalls[54] = sys._allow; // setsockopt
    syscalls[55] = sys._allow; // getsockopt
    syscalls[56] = sys._allow; // clone
    syscalls[57] = sys._allow; // fork
    syscalls[58] = sys._allow; // vfork
    syscalls[59] = sys.execve;
    syscalls[62] = sys.kill;
    syscalls[63] = sys._allow; // uname
    syscalls[76] = sys.truncate;
    syscalls[77] = sys._allow; // ftruncate
    syscalls[79] = sys._allow; // getcwd
    syscalls[80] = sys.chdir;
    syscalls[82] = sys.rename;
    syscalls[83] = sys.mkdir;
    syscalls[84] = sys.rmdir;
    syscalls[85] = sys.creat;
    syscalls[86] = sys.link;
    syscalls[87] = sys.unlink;
    syscalls[88] = sys.symlink;
    syscalls[89] = sys.readlink;
    syscalls[90] = sys.chmod;
    syscalls[92] = sys.chown;
    syscalls[94] = sys.lchown;
    syscalls[101] = sys.ptrace;
    syscalls[132] = sys.utime;
    syscalls[133] = sys.mknod;
    syscalls[137] = sys.statfs;
    syscalls[158] = sys._allow; // arch_prctl
    syscalls[161] = sys.chroot;
    syscalls[163] = sys.acct;
    syscalls[165] = sys.mount;
    syscalls[166] = sys.umount;
    syscalls[167] = sys.swapon;
    syscalls[168] = sys.swapoff;
    syscalls[186] = sys._allow;
    syscalls[218] = sys._allow; // set_tid_address
    syscalls[234] = sys._allow; // tgkill
    syscalls[231] = sys._allow; // exit_group
    syscalls[235] = sys.utimes;
    syscalls[257] = sys.openat;
    syscalls[258] = sys.mkdirat;
    syscalls[259] = sys.mknodat;
    syscalls[260] = sys.fchownat;
    syscalls[261] = sys.futimesat;
    syscalls[262] = sys.newfstatat;
    syscalls[263] = sys.unlinkat;
    syscalls[264] = sys.renameat;
    syscalls[265] = sys.linkat;
    syscalls[266] = sys.symlinkat;
    syscalls[267] = sys.readlinkat;
    syscalls[268] = sys.fchmodat;
    syscalls[269] = sys.faccessat;
    syscalls[293] = sys._allow; // pipe2
    syscalls[273] = sys._allow; // set_robust_list
    syscalls[274] = sys._allow; // get_robust_list
    syscalls[280] = sys.utimensat;
    syscalls[302] = sys._allow; // prlimit64
    syscalls[316] = sys.renameat2;
    syscalls[310] = sys._allow; // process_vm_readv
    syscalls[311] = sys._allow; // process_vm_writev
    syscalls[318] = sys._allow; // get_random
    syscalls[322] = sys.execveat;
    syscalls[332] = sys.statx;
    syscalls[334] = sys._allow; // rseq

    var status: c.siginfo_t = undefined;

    while (true) {
        var sig: i32 = 0;
        pid = c.waitpid(-1, @ptrCast(&status), 0);
        // std.debug.print("PID: {}\n", .{pid});
        // debug.print("Status: {}\n", .{status});
        if (pid == -1) {
            debug.print("Exited, No more children!\n", .{});
            break;
        }

        switch ((status.signo >> 8) & 0xff) {
            0 => {
                debug.print("{}: SUCCESS\n", .{pid});
                _ = linux.ptrace(C.PTRACE_DETACH, pid, 0, 0, 0);
                if (context.getPtr(pid)) |cpid| {
                    if (cpid.file) |file| {
                        file.close();
                        cpid.file = null;
                    }
                }

                if (std.mem.indexOfAny(C.pid_t, pids.items, &.{pid})) |i| {
                    _ = pids.swapRemove(i);
                }
            },
            c.SIG.TRAP => {
                switch (status.signo >> 16) {
                    0 => {
                        debug.print("PTRACE RESET\n", .{});
                        const pctx = context.getPtr(pid).?;
                        if (pctx.file) |file| {
                            file.close();
                            pctx.file = null;
                        }
                    },
                    C.PTRACE_EVENT_SECCOMP => {
                        const pctx = context.getPtr(pid).?;

                        var regs: C.struct_user_regs_struct = undefined;

                        _ = linux.ptrace(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs), 0);
                        const sysn: usize = switch (builtin.target.cpu.arch) {
                            .x86 => regs.orig_eax,
                            .x86_64 => regs.orig_rax,
                            else => @panic("CPU not implemented"),
                        };

                        if (sysn < syscalls.len) {
                            try syscalls[sysn](pctx, &regs);
                        } else {
                            std.debug.print("run-secure: Unknown SYSCALL {}\n", .{sysn});
                            if (!allow_unknown_syscalls) std.process.exit(1);
                        }

                        if (pctx.unimplemented) {
                            debug.print("Syscall not implemented: {}\n", .{sysn});
                            std.process.exit(1);
                        }

                        _ = linux.ptrace(linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs), 0);

                        pctx._resume();
                    },
                    C.PTRACE_EVENT_FORK => {
                        debug.print("{}: FORK\n", .{pid});
                    },
                    C.PTRACE_EVENT_VFORK => {
                        debug.print("{}: VFORK\n", .{pid});
                    },
                    C.PTRACE_EVENT_CLONE => {
                        debug.print("{}: CLONE\n", .{pid});
                    },
                    C.PTRACE_EVENT_EXEC => {
                        debug.print("EXEC\n", .{});
                    },
                    C.PTRACE_EVENT_EXIT => {
                        debug.print("EXIT\n", .{});
                    },
                    C.PTRACE_EVENT_STOP => {
                        debug.print("{}: EVENT_STOP\n", .{pid});
                    },
                    else => {
                        debug.print("Unknown event {}\n", .{status.signo >> 16});
                        sig = status.signo >> 8;
                    },
                }
            },
            c.SIG.STOP => {
                debug.print("{}: STOP\n", .{pid});

                if (!context.contains(pid)) {
                    try pids.append(alloc, pid);
                    try context.put(pid, ContextPID{
                        .pid = pid,
                        .pids = &pids,
                        .alloc = alloc,
                        .db = &db,
                        .allow_all = allow_all,
                        .allow_kill = allow_kill,
                        .interactive = interactive,
                    });
                    _ = linux.ptrace(C.PTRACE_SEIZE, pid, 0, 0, 0);
                    _ = linux.ptrace(C.PTRACE_SETOPTIONS, pid, 0, C.PTRACE_O_EXITKILL | C.PTRACE_O_TRACECLONE | C.PTRACE_O_TRACEFORK | C.PTRACE_O_TRACEVFORK | C.PTRACE_O_TRACESECCOMP, 0);
                    _ = linux.ptrace(C.PTRACE_CONT, pid, 0, 0, 0);
                } else {
                    sig = status.signo >> 8;
                }
            },
            else => {
                sig = status.signo >> 8;
            },
        }

        _ = linux.ptrace(C.PTRACE_CONT, pid, 0, @intCast(sig), 0);
    }

    debug.print("Results:\n", .{});
    const paths = try db.getPaths();
    if (base.DEBUG) {
        try std.zon.stringify.serialize(paths, .{}, std.io.getStdErr().writer());
    }
    debug.print("\n", .{});

    if (save) {
        var file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try std.zon.stringify.serialize(paths, .{}, file.writer());
        debug.print("File {s} saved with all perms\n", .{file_path});
    }

    db.freePaths(paths);
    try db.deinit();
}
