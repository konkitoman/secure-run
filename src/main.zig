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

pub fn _deny(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    if (builtin.cpu.arch == .x86_64) {
        std.debug.print("Syscall not allowed: {}\n", .{regs.orig_rax});
    }

    cpid.unimplemented = true;
}

pub fn _allow(cpid: *ContextPID, regs: *C.struct_user_regs_struct) !void {
    _ = cpid;
    _ = regs;
}

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
        const paths = std.zon.parse.fromSlice([]const base.DB.Path, alloc, @ptrCast(data), &status, .{}) catch |err| {
            std.debug.print("Error {}: {}\n", .{ err, status });
            std.process.exit(1);
        };
        debug.print("Status: {}\n", .{status});

        for (paths) |path| {
            try db.add(path.@"0", path.@"1");
        }

        std.zon.parse.free(alloc, paths);
        alloc.free(data);
    } else |err| {
        debug.print("Cannot open: {s} {}\n", .{ file_path, err });
    }

    {
        const paths = try db.getPaths();
        defer db.freePaths(paths);

        if (base.DEBUG) {
            debug.print("Permissions: ", .{});
            try std.zon.stringify.serialize(paths, .{}, std.io.getStdErr().writer());
            debug.print("\n", .{});
        }
    }

    var syscalls: [457]*const fn (*ContextPID, *C.struct_user_regs_struct) anyerror!void = undefined;
    @memset(&syscalls, if (allow_unknown_syscalls) _allow else _deny);

    syscalls[0] = _allow; // read
    syscalls[1] = _allow; // write
    syscalls[2] = sys.open;
    syscalls[3] = _allow; // close
    syscalls[4] = sys.stat;
    syscalls[5] = _allow; // fstat
    syscalls[6] = sys.lstat;
    syscalls[7] = _allow; // pool
    syscalls[8] = _allow; // lseek
    syscalls[9] = _allow; // mmap
    syscalls[10] = _allow; // mprotect
    syscalls[11] = _allow; // munmap
    syscalls[12] = _allow; // brk
    syscalls[13] = _allow; // rt_sigaction
    syscalls[14] = _allow; // rt_sigprocmask
    syscalls[15] = _allow; // rt_sigreturn
    syscalls[16] = _allow; // ioctl
    syscalls[17] = _allow; // pread64
    syscalls[18] = _allow; // pwrite64
    syscalls[19] = _allow; // readv
    syscalls[20] = _allow; // writev
    syscalls[21] = sys.access;
    syscalls[22] = _allow; // pipe
    syscalls[23] = _allow; // select
    syscalls[24] = _allow; // sched_yield
    syscalls[25] = _allow; // mremap
    syscalls[26] = _allow; // msync
    syscalls[27] = _allow; // mincore
    syscalls[28] = _allow; // madvise
    syscalls[29] = _allow; // shmget
    syscalls[30] = _allow; // shmat
    syscalls[31] = _allow; // shmctl
    syscalls[32] = _allow; // dup
    syscalls[33] = _allow; // dup2
    syscalls[34] = _allow; // pause
    syscalls[35] = _allow; // nanosleep
    syscalls[36] = _allow; // getitimer
    syscalls[37] = _allow; // alarm
    syscalls[38] = _allow; // setitimer
    syscalls[39] = _allow; // getpid
    syscalls[40] = _allow; // sendfile
    syscalls[41] = if (network) _allow else _deny; // socket
    syscalls[42] = if (network) _allow else _deny; // connect
    syscalls[43] = if (network) _allow else _deny; // accept
    syscalls[44] = _allow; // sendto
    syscalls[45] = _allow; // recvfrom
    syscalls[46] = _allow; // sendmsg
    syscalls[47] = _allow; // recvmsg
    syscalls[48] = _allow; // shutdown
    syscalls[49] = if (network) _allow else _deny; // bind
    syscalls[50] = if (network) _allow else _deny; // listen
    syscalls[51] = _allow; // getsockname
    syscalls[52] = _allow; // getpeername
    syscalls[53] = _allow; // socketpair
    syscalls[54] = _allow; // setsockopt
    syscalls[55] = _allow; // getsockopt
    syscalls[56] = _allow; // clone
    syscalls[57] = _allow; // fork
    syscalls[58] = _allow; // vfork
    syscalls[59] = sys.execve;
    syscalls[60] = _allow; // exit
    syscalls[61] = _allow; // wait4
    syscalls[62] = sys.kill;
    syscalls[63] = _allow; // uname
    syscalls[64] = _allow; // semget
    syscalls[65] = _allow; // semop
    syscalls[66] = _allow; // semctl
    syscalls[67] = _allow; // semdt
    syscalls[68] = _allow; // msgget
    syscalls[69] = _allow; // msgsnd
    syscalls[70] = _allow; // msgrcv
    syscalls[71] = _allow; // msgctl
    syscalls[72] = _allow; // fcntl
    syscalls[73] = _allow; // flock
    syscalls[74] = _allow; // fsync
    syscalls[75] = _allow; // fdatasync
    syscalls[76] = sys.truncate;
    syscalls[77] = _allow; // ftruncate
    syscalls[79] = _allow; // getcwd
    syscalls[80] = sys.chdir;
    syscalls[81] = _allow; // fchdir
    syscalls[82] = sys.rename;
    syscalls[83] = sys.mkdir;
    syscalls[84] = sys.rmdir;
    syscalls[85] = sys.creat;
    syscalls[86] = sys.link;
    syscalls[87] = sys.unlink;
    syscalls[88] = sys.symlink;
    syscalls[89] = sys.readlink;
    syscalls[90] = sys.chmod;
    syscalls[91] = _allow; // fchmod
    syscalls[92] = sys.chown;
    syscalls[93] = _allow; // fchown
    syscalls[94] = sys.lchown;
    syscalls[95] = _allow; // umask
    syscalls[96] = _allow; // gettimeofday
    syscalls[97] = _allow; // getrlimit
    syscalls[98] = _allow; // getrusage
    syscalls[99] = _allow; // sysinfo
    syscalls[100] = _allow; // times
    syscalls[101] = sys.ptrace;
    syscalls[102] = _allow; // getuid
    syscalls[103] = _allow; // syslog
    syscalls[104] = _allow; // getgid
    syscalls[105] = _allow; // setuid
    syscalls[106] = _allow; // setgid
    syscalls[107] = _allow; // geteuid
    syscalls[108] = _allow; // getegid
    syscalls[109] = _allow; // setpgid
    syscalls[110] = _allow; // getppid
    syscalls[111] = _allow; // getpgrp
    syscalls[112] = _allow; // setsid
    syscalls[113] = _allow; // setreuid
    syscalls[114] = _allow; // setregid
    syscalls[115] = _allow; // getgroups
    syscalls[116] = _allow; // setgroups
    syscalls[117] = _allow; // setresuid
    syscalls[118] = _allow; // getresuid
    syscalls[119] = _allow; // setresgid
    syscalls[120] = _allow; // getresgid
    syscalls[121] = _allow; // getpgid
    syscalls[122] = _allow; // setfsuid
    syscalls[123] = _allow; // setfsgid
    syscalls[124] = _allow; // getsid
    syscalls[125] = _allow; // capget
    syscalls[126] = _allow; // capset
    syscalls[127] = _allow; // rt_sigpending
    syscalls[128] = _allow; // rt_sigtimedwait
    syscalls[129] = _allow; // rt_sigqueueinfo
    syscalls[130] = _allow; // rt_sigsuspend
    syscalls[131] = _allow; // signalstack
    syscalls[132] = sys.utime;
    syscalls[133] = sys.mknod;
    syscalls[135] = _allow; // personality
    syscalls[136] = _allow; // ustat
    syscalls[137] = sys.statfs;
    syscalls[138] = _allow; // fstatfs
    syscalls[139] = _allow; // sysfs
    syscalls[140] = _allow; // getpriority
    syscalls[141] = _allow; // setprioritykj
    syscalls[142] = _allow; // sched_setparam
    syscalls[143] = _allow; // sched_getparam
    syscalls[144] = _allow; // sched_setscheduler
    syscalls[145] = _allow; // sched_getscheduler
    syscalls[146] = _allow; // sched_get_priority_max
    syscalls[147] = _allow; // sched_get_priority_min
    syscalls[148] = _allow; // sched_rr_get_interval
    syscalls[149] = _allow; // mlock
    syscalls[150] = _allow; // munlock
    syscalls[151] = _allow; // mlockall
    syscalls[152] = _allow; // munlockall
    syscalls[153] = _allow; // vhangup
    syscalls[154] = _allow; // modify_ldt
    syscalls[155] = _allow; // pivot_root
    syscalls[156] = _allow; // _sysctl
    syscalls[157] = _allow; // prctl
    syscalls[158] = _allow; // arch_prctl
    syscalls[159] = _allow; // adjtimeex
    syscalls[160] = _allow; // setrlimit
    syscalls[161] = sys.chroot;
    syscalls[162] = _allow; // sync
    syscalls[163] = sys.acct;
    syscalls[164] = _allow; // settimeofday
    syscalls[165] = sys.mount;
    syscalls[166] = sys.umount;
    syscalls[167] = sys.swapon;
    syscalls[168] = sys.swapoff;
    syscalls[169] = _allow; // reboot
    syscalls[170] = _allow; // sethostname
    syscalls[171] = _allow; // setdomainname
    syscalls[172] = _allow; // iopl
    syscalls[173] = _allow; // ioperm
    syscalls[175] = _allow; // init_module
    syscalls[176] = _allow; // delete_module
    syscalls[179] = _allow; // quotactl
    syscalls[186] = _allow; // getid
    syscalls[187] = _allow; // readahead
    syscalls[188] = sys.setxattr;
    syscalls[189] = sys.lsetxattr;
    syscalls[190] = _allow; // fsetxattr
    syscalls[191] = sys.getxattr;
    syscalls[192] = sys.lgetxattr;
    syscalls[193] = _allow; // fgetxattr
    syscalls[194] = sys.listxattr;
    syscalls[195] = sys.llistxattr;
    syscalls[196] = _allow; // flistxattr
    syscalls[197] = sys.removexattr;
    syscalls[198] = sys.lremovexattr;
    syscalls[199] = _allow; // lremovexattr
    syscalls[200] = _allow; // tkill
    syscalls[201] = _allow; // time
    syscalls[202] = _allow; // futex
    syscalls[203] = _allow; // sched_setaffinity
    syscalls[204] = _allow; // sched_getaffinity
    syscalls[206] = _allow; // io_setup
    syscalls[207] = _allow; // io_destroy
    syscalls[208] = _allow; // io_getevents
    syscalls[209] = _allow; // io_submit
    syscalls[210] = _allow; // io_cancel
    syscalls[213] = _allow; // epoll_create
    syscalls[216] = _allow; // remap_file_pages
    syscalls[217] = _allow; // getdents64
    syscalls[218] = _allow; // set_tid_address
    syscalls[219] = _allow; // restart_syscall
    syscalls[220] = _allow; // semtimedop
    syscalls[221] = _allow; // fadvise64
    syscalls[222] = _allow; // timer_create
    syscalls[223] = _allow; // timer_settime
    syscalls[224] = _allow; // timer_gettime
    syscalls[225] = _allow; // timer_getoverrun
    syscalls[226] = _allow; // timer_delete
    syscalls[227] = _allow; // clock_settime
    syscalls[228] = _allow; // clock_gettime
    syscalls[229] = _allow; // clock_getres
    syscalls[230] = _allow; // clock_nanosleep
    syscalls[231] = _allow; // exit_group
    syscalls[232] = _allow; // epoll_wait
    syscalls[233] = _allow; // epoll_ctl
    syscalls[234] = _allow; // tgkill
    syscalls[235] = sys.utimes;
    syscalls[237] = _allow; // mbind
    syscalls[238] = _allow; // set_mempolicy
    syscalls[239] = _allow; // get_mempolicy
    syscalls[240] = _allow; // mq_open
    syscalls[241] = _allow; // mq_unlink
    syscalls[242] = _allow; // mq_timedsend
    syscalls[243] = _allow; // mq_timedreceive
    syscalls[244] = _allow; // mq_notify
    syscalls[245] = _allow; // mq_getsetattr
    syscalls[246] = _allow; // kexec_load
    syscalls[247] = _allow; // waitid
    syscalls[248] = _allow; // add_key
    syscalls[249] = _allow; // request_key
    syscalls[250] = _allow; // keyctl
    syscalls[251] = _allow; // ioprio_set
    syscalls[252] = _allow; // ioprio_get
    syscalls[253] = _allow; // inotify_init
    syscalls[254] = _allow; // inotify_add_watch
    syscalls[255] = _allow; // inotify_rm_watch
    syscalls[256] = _allow; // migrate_pages
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
    syscalls[270] = _allow; // pselect6
    syscalls[271] = _allow; // ppoll
    syscalls[272] = _allow; // unshare
    syscalls[273] = _allow; // set_robust_list
    syscalls[274] = _allow; // get_robust_list
    syscalls[275] = _allow; // splice
    syscalls[276] = _allow; // tee
    syscalls[277] = _allow; // sync_file_range
    syscalls[278] = _allow; // vmsplice
    syscalls[279] = _allow; // move_pages
    syscalls[280] = sys.utimensat;
    syscalls[281] = _allow; // epoll_pwait
    syscalls[282] = _allow; // signalfd
    syscalls[283] = _allow; // timerfd_create
    syscalls[284] = _allow; // eventfd
    syscalls[285] = _allow; // fallocate
    syscalls[286] = _allow; // timerfd_settime
    syscalls[287] = _allow; // timerfd_gettime
    syscalls[288] = if (network) _allow else _deny; // accept4
    syscalls[289] = _allow; // signalfd64
    syscalls[290] = _allow; // eventfd2
    syscalls[291] = _allow; // epoll_create1
    syscalls[292] = _allow; // dup3
    syscalls[293] = _allow; // pipe2
    syscalls[294] = _allow; // inotify_init1
    syscalls[295] = _allow; // preadv
    syscalls[296] = _allow; // pwritev
    syscalls[297] = _allow; // rt_tgsigqueueinfo
    syscalls[298] = _allow; // pref_event_open
    syscalls[299] = _allow; // recvmmsg
    syscalls[300] = _allow; // fanotify_init
    syscalls[301] = _allow; // fanotify_mark
    syscalls[302] = _allow; // prlimit64
    syscalls[305] = _allow; // clock_adjtime
    syscalls[306] = _allow; // syncfs
    syscalls[307] = _allow; // sendmmsg
    syscalls[308] = _allow; // setns
    syscalls[309] = _allow; // getcpu
    syscalls[310] = _deny; // process_vm_readv
    syscalls[311] = _deny; // process_vm_writev
    syscalls[312] = _allow; // kcmp
    syscalls[313] = _allow; // finit_module
    syscalls[314] = _allow; // sched_setattr
    syscalls[315] = _allow; // sched_getattr
    syscalls[316] = sys.renameat2;
    syscalls[317] = _allow; // seccomp
    syscalls[318] = _allow; // get_random
    syscalls[319] = _allow; // memfd_create
    syscalls[320] = _allow; // kexec_file_load
    syscalls[321] = _allow; // bpf
    syscalls[322] = sys.execveat;
    syscalls[323] = _allow; // userfaultfd
    syscalls[324] = _allow; // membarrier
    syscalls[325] = _allow; // mlock2
    syscalls[326] = _allow; // copy_file_range
    syscalls[327] = _allow; // preadv2
    syscalls[328] = _allow; // pwritev2
    syscalls[329] = _allow; // pkey_mprotect
    syscalls[330] = _allow; // pkey_alloc
    syscalls[331] = _allow; // pkey_free
    syscalls[332] = sys.statx;
    syscalls[333] = _allow; // io_pgetevents
    syscalls[334] = _allow; // rseq
    syscalls[424] = _deny; // pidfd_send_signal
    syscalls[425] = _allow; // io_uring_setup
    syscalls[426] = _allow; // io_uring_enter
    syscalls[427] = _allow; // io_uring_register
    syscalls[435] = _allow; // clone3
    syscalls[436] = _allow; // close_range
    syscalls[438] = _allow; // pidfd_getfd
    syscalls[439] = sys.faccessat2;
    syscalls[441] = _allow; // epoll_pwait2
    syscalls[443] = _allow; // quotactl_fd
    syscalls[447] = _allow; // memfd_secret
    syscalls[449] = _allow; // futex_waitv
    syscalls[453] = _allow; // map_shadow_stack
    syscalls[451] = _allow; // cachestat
    syscalls[454] = _allow; // futex_wake
    syscalls[455] = _allow; // futex_wait
    syscalls[456] = _allow; // futex_requeue

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
