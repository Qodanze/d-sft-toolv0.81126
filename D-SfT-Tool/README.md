# D-SfT Tool

A lightweight C++/Qt6 dev tool for testing and debugging programs on Linux —
a GUI with a terminal soul.

## What it does

- **Explorer tree (left)** — add any folder or file with `+ Add Path...`.
  Folders expand like a file manager (arbitrarily deep, lazily loaded, with
  horizontal scroll) and list EVERY file inside: executables, scripts
  (sh/bash/py/pl/rb, shebang or exec bit), `.desktop` entries — and
  non-runnable files (`.png`, `.mp4`, `.mp3`, `.zip`, ...) shown muted with a
  **content-sniffed type icon** (mime magic bytes, so a renamed file is still
  recognized) and a color-coded type label. Runnables glow **green + bold**
  while they run. Double-click or select + `Run` to launch.
- **Terminal output (right)** — color-coded:
  - white = the program's stdout
  - soft orange = stderr
  - **yellow bold = activity** — `<app>: run <cmd>`, `<app>: create <file>`,
    `<app>: rm <file>`, `<app>: waiting for input on stdin` — including every
    child the program spawns, however deep (script → script → script → ...).
- **Arguments** — type them in the Args box; `.desktop` field codes
  (`%f %u ...`) are substituted, flatpak `@@u %u @@` forwarding wrappers are
  unwrapped automatically, `[Desktop Action]` sub-entries are runnable
  variants under the entry.
- **stdin** — the `stdin >` box feeds the running program; the box flashes
  yellow and an activity line appears when the program is waiting for input.
- **Auto-scroll** — on: output follows the bottom; off: new lines still
  appear but the view stays where you're reading.
- **Kill orphans on exit** — when a program reports `exit code 0` but left
  children running (Discord-style), they are detected and killed.
- **■ Stop** — kills the WHOLE tree: process group + /proc walk + shim
  registry (catches `setsid` escapees), escalating SIGTERM → SIGKILL; inside
  a kernel jail scope it also SIGKILLs the whole cgroup (`cgroup.kill`).
- **⚙ Limitations...** (was "Sandbox") — click the entry's gear (or the
  toolbar button; it's GRAY until a runnable entry is selected). One dialog
  with three sections:
  - **Disk limit (MB)** + `Terminate?` + `Delete & limit disk usage?` —
    Terminate kills the whole tree when the limit is hit; with Terminate off,
    Delete still wipes everything the program created the moment the limit
    is hit and keeps the program running (writes are blocked at the limit,
    freed, and it can continue — limited but alive). Both off = watch only.
  - **RAM limit (MB)** (real resident memory — VmRSS of the whole tree,
    the same number System Monitor shows) with a **mode switch** — exactly
    one of:
    - **Terminate** — kill the whole tree the moment it passes the limit;
    - **Own sandbox** — a REAL kernel jail: the program runs as if on a PC
      that only HAS that much RAM. Enforced by a cgroup v2 scope
      (`systemd-run --user --scope -p MemoryMax=<mb>M -p MemorySwapMax=0`) —
      the kernel physically caps resident RAM for the whole tree, raw `mmap`
      and static binaries included; going past the limit means failed
      allocations or a kernel OOM-kill, exactly like on constrained
      hardware. Requires a systemd user session (probed automatically);
      without one it falls back to `RLIMIT_AS` (loud yellow warning — that
      one counts virtual memory, so it is stricter than the RSS meter and
      GUI apps may fail to start). The LD_PRELOAD malloc filter stays
      active as a first layer, so malloc-based apps fail their allocations
      gracefully instead of dying.
    - **Watch only** — no action, just the live meter.
  - **CPU limit (%)** of ALL cores (System Monitor semantics: 100% = the
    whole machine), same mode switch: **Terminate** (kill when sustained
    over the limit) / **Own sandbox** (throttled to N% via SIGSTOP/SIGCONT
    duty-cycling, like running on a slower PC) / **Watch only**.
  The Limits column shows a summary (e.g. `D90T R256J C20J`: T=terminate,
  D=delete, J=jail). The status bar shows live disk/RAM/CPU usage while
  running — each with a terminal-style block gauge that shifts
  green → amber → red as usage approaches the limit, and a green
  ● running / gray ○ idle state dot.
- **List extras** — right-click menu has **Clear all** (wipe every root at
  once), **Select all (Ctrl+A)**, per-root Remove, Run and Limitations.
  Ctrl+A / the menu action selects every entry (pairs with the batch Run
  queue).
- **Search** — the box above the tree fuzzy-matches while you type:
  "kansole" finds konsole.desktop (typo tolerance), "kon" matches anything
  containing it, folders match too. The best match is auto-selected —
  Enter runs it, Esc clears.
- **Multi-select** — Ctrl+click toggles entries, Shift+click and
  **Alt+click = range select** (click obj2, Alt+click obj5 → 2..5 selected).
  ▶ Run runs all selected programs one after another (queued); ■ Stop
  cancels the queue.
- **+ Folder / + File(s)** — add a whole folder tree or pick individual
  files directly (no folder needed). Right-click a root to remove it.

## How detection works

Launched processes get `LD_PRELOAD=libdsftshim.so` (inherited by the whole
tree). The shim hooks open/fopen/fwrite/close, unlink/remove, mkdir/rename,
execve/execvp, fork, and stdin reads (read/fgets/getline), and reports
newline-terminated events over an AF_UNIX datagram socket:
`F` register, `E` exec, `C` create, `D` delete, `W` bytes-written,
`I` stdin-wait, `Q` quota-hit. Byte totals live in a POSIX shared-memory
segment shared by the whole tree (robust mutex), so quota enforcement is
global across all children. Settings persist in `data/config.json`.

## Build & run

```sh
cd D-SfT-Tool
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/dsft-tool            # GUI
```

A ready-made launcher ships in the repo root: `dsft-tool.desktop`. Copy it to
`~/.local/share/applications/` to get D-SfT into your app grid / taskbar with
a proper icon (the window icon is also set in-app; on Wayland the taskbar
matches the window to this .desktop file by app-id).

## Self test (86 checks)

```sh
QT_QPA_PLATFORM=offscreen ./build/dsft-tool --selftest
```

Covers: .desktop parsing (flatpak wrappers, actions, arg substitution),
deep folder recursion without re-adding children, stdout capture, create/rm
detection, multi-level script exec detection, stop-kills-whole-chain,
sandbox quota hit + partial-file deletion, sandbox bypass via fork+exec'd
`dd`, RAM terminate + the own-ram kernel jail (malloc eater AND a raw-mmap
bypass program), a real Qt app (konsole) with and without the jail,
orphan-after-exit-0 detection + kill, stdin feeding + wait detection,
and end-to-end .desktop runs. A screenshot is saved to `selftest-ui.png`.

Test programs live in `testdata/` (hello, writer, bypass, orphan, remover,
echoline, chain scripts, sample .desktop).

## Limitations (honest ones)

- Static binaries and setuid programs bypass LD_PRELOAD → no events from
  them (the process group is still killed; RAM-wise the cgroup jail still
  caps them — they just report no activity).
- Bytes written via glibc-internal syscalls that never pass a hookable libc
  call (mmap'd file writes) are not counted.
- The shim hooks the C library's functions, so programs doing raw
  `syscall(SYS_write, ...)` are invisible to activity/accounting.
- GUI apps that daemonize with double-fork are still caught (registry
  membership), but only while the shim is loaded in them.

## Known-good environment

Arch Linux, Qt 6.12, gcc 15, Wayland or offscreen. No other dependencies.
