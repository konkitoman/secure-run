# Secure Run

Everything that you do using this app is your responsibility.

This app allows you to run a app more securely.

This app can be used to see what files a program accesses and what permissions using the `-akns` flags.

You can use `-a` to allow access to all the files.
You can use `-k` to allow the program to send a kill to any process.
You can use `-n` to allow network syscalls.
You can use `-s` to save the `permissions.zon` after all the processes ended.
You can use `-u` to allow unknown syscalls.
You can use `-i` for interactive mode when the process tries to access a file or kill a process.

# Permissions

The `permissions.zon` will be used from the current directory in that the `secure-run` is runed.

## Format

permissions are laid out in a list.

Every entry has a `perm` and `path` fields

Falid `perm`
- `none` not permission, secure-run will never save this permission with `-s`
- `f` the file will be visible to the program
- `r` the file will have read permissions to the program
- `w` the file will have write permissions to the program
- `x` the file will have executabile permissions to the program

When we have more permissions they will be laid out like: `frwx` for all of them.
- `xwrf` is not a valid `perm`.
- `fr` is a valid `perm`.
- `fw` is a valid `perm`.
- `fwr` is not a valid `perm`.

The `path` can be a absolute path or a wild path.
A path should always start with `/`.
A wild path will be `/usr/bin/*` what permission this has set any other file inside this file will have that permission.
You can have a read permission to `/usr/*` and a none to `/usr/bin/*` to restrict access to `/usr/bin`

This is with not permissions. 
```zon
.{
  
}
```

This is that allows read access any file from `/etc`
```zon
.{
    .{ .perm = .fr, .path = "/etc/*" },
}
```

This is the recommended `permissions.zon` for the most programs to work using interactive mode.

```zon
.{
    .{ .perm = .fr, .path = "/lib/*" },
    .{ .perm = .frx, .path = "/bin/*" },
    .{ .perm = .fr, .path = "/usr/lib/*" },
    .{ .perm = .frx, .path = "/usr/bin/*" },
    .{ .perm = .fr, .path = "/etc/*" },
    .{ .perm = .fr, .path = "/sys/*" },
    .{ .perm = .fr, .path = "/var/*" },
}
```
