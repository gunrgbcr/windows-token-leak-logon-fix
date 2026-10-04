# Windows 11 kernel token leak: why the ForegroundLockTimeout fix does not survive a logon, and one that does

Windows 11 25H2 leaks one kernel security token for every process that creates a child process. On a developer machine that adds up to millions of tokens and many GB of kernel memory within days. Setting `ForegroundLockTimeout` to 0 stops it, as [bentoner/windows-token-leak](https://github.com/bentoner/windows-token-leak) found. This repo adds three things:

1. **Why the fix comes undone at every logon:** Windows' own logon code overwrites the value with 2147483647 after reading the registry, so the saved registry value never takes effect.
2. **Why setting it is sometimes refused (error 87):** Windows accepts the change only from a process that may take the foreground, and at 2147483647 that is almost only the window you are using.
3. **A fix that survives restarts**, plus measurements before and after.

Tested on Windows 11 25H2 build 26200.9550 (`win32kfull.sys` 10.0.26100.9549). The same code is in `win32kfull.sys` 10.0.26100.9444.

## Check whether you are affected

```
python flt_fix.py              # prints the live ForegroundLockTimeout and the live "Toke" kernel object count
python flt_fix.py --test 1000  # starts 1000 parent+child process pairs and reports the Toke change
```

A live value of `2147483647` and a `--test 1000` result near **+1000** means you are leaking. A result near 0 (± a few hundred of background noise) means you are not.

## The fix

**Every time you log on, set the live value to 0 from a window you opened yourself.** The simplest way is one line in your PowerShell profile (`notepad $PROFILE`, see [`profile-snippet.ps1`](profile-snippet.ps1)):

```powershell
python "C:\path\to\flt_fix.py" --profile
```

Every new PowerShell window then sets the value to 0 if it is not 0 already. It prints one line when it acts (`token-leak fix: ForegroundLockTimeout 2147483647 -> 0`) and nothing otherwise. It adds about 50 ms to opening a window. Without the profile, run `python flt_fix.py --fix` in a terminal after each logon.

**Trade-off:** with the value at 0, any application may take the foreground (steal focus).

**Tokens that already leaked are freed only by a full restart.** With Fast Startup on, "Shut down" saves the kernel and restores it, leak included; use **Restart**, or turn Fast Startup off (`powercfg /h off`, from an administrator prompt).

## What doesn't work

| Approach | Result |
|---|---|
| Registry `HKCU\Control Panel\Desktop\ForegroundLockTimeout = 0` | Overwritten at every logon (see below). Here the registry held 0 while the live value read 2147483647 after the restart. |
| `SystemParametersInfo(..., SPIF_UPDATEINIFILE)` once | Works until the next logon, then the same overwrite. |
| A Startup-folder shortcut that sets it at logon | Unreliable: reported success on 2 of 3 boots, failed on the other (Windows started it about a minute after logon, another window already had focus, and all 25 attempts got error 87). |

## Root cause, read from the code

Disassembly with WinDbg and Microsoft's public symbols. The full listings are in [`evidence/`](evidence/).

**The leak.** `win32kfull!CForegroundLaunch::_CheckAllowForeground` runs for a newly created process:
- `+0x68` gets the parent PID (`PsGetProcessInheritedFromUniqueProcessId`); `+0x125` locks the parent process (`CLockProcessByPid`).
- `+0x3a9` calls **`PsReferencePrimaryToken(parent)`**, which adds a reference to the parent's token.
- `+0x3c9` passes it to `SeQueryAuthenticationIdToken` and compares the logon ID with `luidSystem`. The token pointer is then overwritten and never stored.
- The function (990 lines) contains **no `PsDereferencePrimaryToken`, `ObfDereferenceObject` or `ObDereferenceObject`.** Other win32kfull functions do call `PsDereferencePrimaryToken`; this one doesn't. The reference is never released.

**The gate.** At `+0x198` the function calls `CanForceForeground(parent)`; if that returns TRUE, it jumps to `+0x4a0` and skips the leaking block. The final test in `CanForceForeground` (`+0x425`) is `CInputGlobals::IsTimeFromLastInputEvent(SPI_GETFOREGROUNDLOCKTIMEOUT)`, i.e. `(now - lastInput) > ForegroundLockTimeout`:
- **0:** true as soon as any time has passed since the last input, so the leak is skipped.
- **200000 (the documented default):** leaks whenever there was input in the last 200 seconds, i.e. during normal use.
- **2147483647:** true only after 24.8 days without input, so background parents leak almost always.

**The logon overwrite.** `win32kfull!LoadCPUserPreferences`, called from `xxxUpdatePerUserSystemParameters` while the per-user settings are loaded at logon:
- reads the per-user DWORD settings from the registry (`FastGetProfileValue`), `ForegroundLockTimeout` among them;
- then every path converges at `+0x1e7` and runs straight to `+0x2bb`: `mov ecx,2001h; call UPDWORDPointer; mov dword ptr [rax],7FFFFFFFh`, **with no condition**.
- `win32kbase!UPDWORDPointer(spi)` returns the slot `(spi - 0x2000) >> 1`, so `0x2001` (SET) and `0x2000` (GET) are the same slot: the value `SPI_GETFOREGROUNDLOCKTIMEOUT` returns.

Whatever the registry says, the live value after logon is 2147483647, the setting that leaks the most. The bentoner write-up observed the same thing ("something sets the live value to 2147483647 after logon"); this is that something. Whether a later step resets it on other machines was not traced; check yours with `python flt_fix.py`.

**Why the reset is refused.** `SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT)` fails with error 87 unless the caller may take the foreground. That permission depends on the same timeout, so the setting guards itself: at 0 almost any process may change it; at 2147483647 almost only the focused window's process. From the same background process, the call was refused at one moment and accepted at another, depending on which window had focus. (The exact check in `xxxSystemParametersInfoWorker` was only partly read.)

## Measurements

| What | Value |
|---|---|
| Per child process (pointer count on the parent's token after it exits) | clean token `h1/p32769`; +1 per child (0/1/2/4 children scale exactly) |
| Live kernel dump after 233.7 h uptime | **4,534,913** Token objects, **2,191** Token handles |
| Kernel memory held by leaked tokens | ≈ 13.3 GB (Toke 9.86 GB, SeAt 1.74, SeTd 0.65, SeTl 0.58 non-paged, SeDt 0.48) |
| Leak rate | 13–18 tokens/s with many developer tools running, 1–4/s idle |
| Side effects | process start 200–430 ms (normal 10–20), "out of virtual memory" warning, pagefile grown to 51 GB |
| After the fix: 100,000 `cmd /c cmd /c rem` pairs in 9.2 min | Toke **+176** (leaking: about +100,000) |
| After the fix, three runs of 300 pairs | +133, +14, +1 |
| Profile fix: value set to 2147483647, then a new PowerShell tab opened | `2147483647 -> 0` |
| After a real restart (see note) | live 0; two runs of 300 pairs: −31, −25 |

Note on the restart test: the first PowerShell window opened 47 s after boot and the live value was 0 afterwards. An older Startup-folder script was still installed and also reported success 19 s later, so this restart alone does not show which of the two set it; the profile was shown to work on its own by the `--set 2147483647` test above.

## Not established

- Which code path calls `_CheckAllowForeground` once per process creation (no cross-references in the debugger); the per-child count comes from measurement.
- The exact permission check that returns error 87.
- Whether the logon overwrite applies on every machine or build.

## The real fix (for Microsoft)

1. Add the missing `PsDereferencePrimaryToken` in `CForegroundLaunch::_CheckAllowForeground`.
2. Check whether the unconditional `0x7FFFFFFF` store in `LoadCPUserPreferences` is intended: it overrides the user's setting and arms the leaking path permanently.

## Credits and related reports

- [bentoner/windows-token-leak](https://github.com/bentoner/windows-token-leak): first identified `_CheckAllowForeground` and the `ForegroundLockTimeout = 0` workaround.
- [Microsoft Q&A 5952454](https://learn.microsoft.com/en-gb/answers/questions/5952454/windows-11-25h2-26200-8655-unbounded-paged-pool-le): the original report (26200.8655), with the ETW allocation stack.
- [openai/codex#30926](https://github.com/openai/codex/issues/30926), [melodic-software/claude-code-plugins#4372](https://github.com/melodic-software/claude-code-plugins/issues/4372): the same leak seen through developer tools that start many processes.

## Files

- [`flt_fix.py`](flt_fix.py): check (`no arguments`), fix (`--fix`, retries for 2 minutes), profile mode (`--profile`, one try, silent when already 0), measure (`--test N`), and `--set N` to recreate the after-logon state for testing. Python 3, standard library only.
- [`profile-snippet.ps1`](profile-snippet.ps1): the line for your PowerShell profile.
- [`evidence/`](evidence/): debugger listings and logs (machine-specific paths removed).
