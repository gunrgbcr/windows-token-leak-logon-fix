"""Windows 11 'Toke' kernel token leak: check, fix and verify the ForegroundLockTimeout workaround.

  python flt_fix.py            show the live ForegroundLockTimeout and the live 'Toke' object count
  python flt_fix.py --fix      set the live ForegroundLockTimeout to 0 (retries for 2 min, for use at logon)
  python flt_fix.py --test N   run N 'cmd /c cmd /c rem' parent+child pairs and report the 'Toke' change

The live value has to be set after every logon: setting it only in the registry does not survive one.
Trade-off: with 0, any app may take the foreground.
"""
import ctypes, subprocess, sys, time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
SPI_GETFOREGROUNDLOCKTIMEOUT, SPI_SETFOREGROUNDLOCKTIMEOUT, SPIF_SENDCHANGE = 0x2000, 0x2001, 2


def flt():
    v = wintypes.DWORD()
    user32.SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, ctypes.byref(v), 0)
    return v.value


def toke():
    """Live 'Toke' pool objects (allocs - frees) from NtQuerySystemInformation(SystemPoolTagInformation)."""
    size = 1 << 20
    while True:
        buf, ret = ctypes.create_string_buffer(size), wintypes.ULONG()
        if ntdll.NtQuerySystemInformation(22, buf, size, ctypes.byref(ret)) & 0xFFFFFFFF == 0xC0000004:
            size *= 2
            continue
        break
    raw = buf.raw
    for i in range(int.from_bytes(raw[0:4], "little")):
        o = 8 + i * 40  # x64 SYSTEM_POOLTAG is 40 bytes
        if raw[o:o + 4] == b"Toke":
            return int.from_bytes(raw[o + 4:o + 8], "little") - int.from_bytes(raw[o + 8:o + 12], "little")
    return -1


def fix():
    for i in range(1, 25):
        ok = user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, None, SPIF_SENDCHANGE)
        err = ctypes.get_last_error()
        if flt() == 0:
            print(f"live ForegroundLockTimeout = 0 (try {i})")
            return 0
        time.sleep(5)
    print(f"failed: set={bool(ok)} error={err} live={flt()} - run it from a foreground terminal")
    return 1


def test(n):
    t0 = toke()
    for _ in range(n):
        subprocess.run(["cmd.exe", "/d", "/c", "cmd.exe", "/d", "/c", "rem"], stdout=subprocess.DEVNULL)
    time.sleep(5)
    t1 = toke()
    print(f"{n} pairs: Toke {t0:,} -> {t1:,} ({t1 - t0:+,}); leaking would be about +{n:,}, fixed is noise")


def profile():
    """One try, silent when already 0; for the PowerShell profile (a new window is the foreground program)."""
    before = flt()
    if before == 0:
        return 0
    user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, None, SPIF_SENDCHANGE)
    err = ctypes.get_last_error()
    print(f"token-leak fix: ForegroundLockTimeout {before} -> {flt()}" + ("" if flt() == 0 else f" (refused, error {err})"))
    return 0 if flt() == 0 else 1


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--fix"]:
        sys.exit(fix())
    if a[:1] == ["--profile"]:
        sys.exit(profile())
    if a[:1] == ["--set"]:  # testing only: --set 2147483647 recreates the after-logon state
        ok = user32.SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, ctypes.c_void_p(int(a[1])), SPIF_SENDCHANGE)
        print(f"set={bool(ok)} error={ctypes.get_last_error()} live={flt()}")
        sys.exit(0 if ok else 1)
    print(f"live ForegroundLockTimeout = {flt()}   live Toke objects = {toke():,}")
    if a[:1] == ["--test"]:
        test(int(a[1]) if len(a) > 1 else 1000)
