# Windows 11 leaks a kernel security token for every process that starts another process

**In one paragraph:** on Windows 11 25H2, every time a program starts a child program, Windows adds one reference to the parent's security token and never releases it. The token (about 3 KB of kernel memory) can then never be freed until the machine restarts. Normal use leaks slowly enough that nobody notices. Developer tools that start thousands of short-lived processes (build tools, git, shells, AI coding agents) leak millions of tokens in days. On my machine that reached about 13 GB of kernel memory after 10 days of uptime. The leak depends on a hidden setting, `ForegroundLockTimeout`: at 0 it doesn't happen. Windows resets that setting to its worst value at every logon, so the setting has to be fixed again after each logon. The fix below does that automatically.

Tested on Windows 11 25H2, build 26200.9550 (`win32kfull.sys` 10.0.26100.9549). The logon overwrite described below is also in `win32kfull.sys` 10.0.26100.9444.

## What it looked like

I had been using Claude Code, an AI coding agent, almost nonstop for a week without restarting. It runs thousands of small commands, and many of those start child processes of their own. After about 10 days of uptime:

- Starting any program took 200–430 ms instead of the usual 10–20 ms.
- Windows logged "a low virtual memory condition" (event 2004), and the page file had grown to 51 GB.
- Yet the programs Windows named as the biggest users held about 1.3 GB at most. The memory was gone into the kernel itself.

## Finding it

**1. Which kernel memory.** Windows tags every kernel allocation with a 4-letter code. Counting them (`NtQuerySystemInformation`, pool tag information) showed the paged pool at 21 GB, and almost all of the excess in tags that belong to security tokens: `Toke` 9.86 GB, `SeAt` 1.74 GB, `SeTd` 0.65 GB, `SeTl` 0.58 GB (non-paged, so always in RAM), `SeDt` 0.48 GB. About **13.3 GB in total**, growing by 13–18 tokens per second while tools were running and 1–4 per second when idle.

**2. Leaked, not just in use.** A live kernel dump counted **4,534,913 token objects, but only 2,191 open handles** to tokens. A token that nobody holds a handle to should be freed. Millions of tokens alive with no handle means something took a *reference* to each one and never gave it back.

**3. What triggers it.** A small test: open a handle to a process's token, let the process run and exit, then read the token's reference count. A process that started nothing leaves a clean count. Every child process it started leaves **exactly one extra reference** on the parent's token: 0, 1, 2 and 4 children give +0, +1, +2 and +4. It made no difference whether the parent was `cmd`, Python, git or bash. So: **one leaked token per process that ever starts a child.**

This is why developer tools make it visible. A single shell command often goes through a launcher that starts the real shell, which starts the program, and tools run such commands constantly. None of this is a bug in those tools; any program that starts processes triggers it.

## Why it happens (read from the code)

I disassembled `win32kfull.sys` with WinDbg and Microsoft's public symbols. The listings are in [`evidence/`](evidence/).

**The missing release.** When a new process starts, Windows checks whether it may take the foreground. That check, `win32kfull!CForegroundLaunch::_CheckAllowForeground`, looks at the parent process:
- `+0x68`: gets the parent's process ID; `+0x125`: locks the parent process.
- `+0x3a9`: calls **`PsReferencePrimaryToken(parent)`**, which adds a reference to the parent's token.
- `+0x3c9`: reads the token's logon ID (`SeQueryAuthenticationIdToken`) and compares it with the SYSTEM logon ID. Then the token pointer is dropped.
- The function (990 lines) contains **no `PsDereferencePrimaryToken`** (and no `ObDereferenceObject` / `ObfDereferenceObject`). The reference is never released.

**When that code runs.** At `+0x198` the function calls `CanForceForeground(parent)`; if it returns TRUE, the code jumps past the leaking block. Its final test (`+0x425`) compares the time since your last keyboard or mouse input with `ForegroundLockTimeout`:
- **0:** passes as soon as any time has passed since the last input, so the leak never runs.
- **200000 (the documented default, 200 s):** leaks whenever you touched the keyboard or mouse in the last 200 seconds, i.e. whenever you're using the machine.
- **2147483647:** passes only after 24.8 days without input, so almost every child process leaks.

On my machine the live value was 2147483647, even though the registry said 200000.

## Why setting it to 0 doesn't stick

Setting `ForegroundLockTimeout` to 0 in the registry (`HKCU\Control Panel\Desktop`) does nothing after the next logon. The reason is in `win32kfull!LoadCPUserPreferences`, which runs at every logon (called from `xxxUpdatePerUserSystemParameters`):
- it reads the per-user settings from the registry, `ForegroundLockTimeout` among them;
- then, on every path, it runs `mov ecx,2001h; call UPDWORDPointer; mov dword ptr [rax],7FFFFFFFh` (at `+0x2bb`), **with no condition**;
- `UPDWORDPointer(spi)` returns the storage slot `(spi - 0x2000) >> 1`, so 0x2001 (set) and 0x2000 (get) are the same slot: the live value.

So whatever the registry says, the live value after logon is 2147483647, the value that leaks the most. Here the registry held 0 while the live value read 2147483647 after a restart.

**And it guards itself.** Setting the live value with `SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT)` fails with error 87 unless the calling process may take the foreground, a permission that depends on this same timeout. At 2147483647, that is almost only the window you are actually using. A program running in the background at logon is refused; a terminal you just opened is allowed.

## The fix

**After each logon, set the live value to 0 from a window you opened yourself.** The simplest way is one line in your PowerShell profile (`notepad $PROFILE`; see [`profile-snippet.ps1`](profile-snippet.ps1)):

```powershell
python "C:\path\to\flt_fix.py" --profile
```

Every new PowerShell window then sets the value to 0 if it isn't 0 already, printing `token-leak fix: ForegroundLockTimeout 2147483647 -> 0` when it acts and nothing otherwise. Without the profile, run `python flt_fix.py --fix` in a terminal after each logon.

- **Trade-off:** with the value at 0, any application may take the foreground (steal focus).
- **Tokens that already leaked are freed only by a full restart.** With Fast Startup on, "Shut down" saves the kernel to disk and restores it, leak included. Use **Restart**, or turn Fast Startup off (`powercfg /h off` from an administrator prompt).

## Proof that it works

| Test | Result |
|---|---|
| 100,000 `cmd /c cmd /c rem` (parent + child) pairs in 9.2 min, after the fix | live `Toke` count **+176**; leaking, it would be about +100,000 |
| Repeated runs of 300 pairs | +133, +14, +1, −31, −25 (background noise; leaking would be about +300 each) |
| Value put back to 2147483647 by hand, then a new PowerShell tab opened | `2147483647 -> 0` |
| Real restart with only the profile line installed (first PowerShell window opened 23 s after boot) | live value 0; two runs of 300 pairs: −4, −55 |

## Check your own machine

```
python flt_fix.py              # live ForegroundLockTimeout and the live Toke object count
python flt_fix.py --test 1000  # starts 1000 parent+child pairs and reports the Toke change
```

A live value of `2147483647` and a `--test 1000` result near **+1000** means you are leaking. Near 0 (give or take a few hundred of background activity) means you are not.

## Not established

- Which code path calls `_CheckAllowForeground` once per new process (the debugger showed no cross-references); the one-per-child count comes from measurement.
- The exact permission check that returns error 87.
- Whether the logon overwrite happens on every machine and build. Check yours with `python flt_fix.py`.

## What Microsoft should fix

1. Add the missing `PsDereferencePrimaryToken` in `CForegroundLaunch::_CheckAllowForeground`.
2. Check whether the unconditional `0x7FFFFFFF` store in `LoadCPUserPreferences` is intended: it overrides the user's setting and keeps the leaking path armed permanently.

## Others who hit the same leak

- [bentoner/windows-token-leak](https://github.com/bentoner/windows-token-leak): an earlier, independent analysis that also traced the leak to `_CheckAllowForeground` and found the `ForegroundLockTimeout = 0` workaround. The logon overwrite above explains why that setting doesn't survive a restart.
- [Microsoft Q&A 5952454](https://learn.microsoft.com/en-gb/answers/questions/5952454/windows-11-25h2-26200-8655-unbounded-paged-pool-le): the same leak on build 26200.8655, with the allocation stack of the leaked tokens (`SeSubProcessToken`).
- [openai/codex#30926](https://github.com/openai/codex/issues/30926) and [melodic-software/claude-code-plugins#4372](https://github.com/melodic-software/claude-code-plugins/issues/4372): the same leak seen through developer tools that start many processes.

## Files

- [`flt_fix.py`](flt_fix.py): check (no arguments), fix (`--fix`, retries for 2 minutes), profile mode (`--profile`, one try, silent when already 0), measure (`--test N`), and `--set N` to put the value back for testing. Python 3, standard library only.
- [`profile-snippet.ps1`](profile-snippet.ps1): the line for your PowerShell profile.
- [`evidence/`](evidence/): debugger listings and logs (machine-specific paths removed).
