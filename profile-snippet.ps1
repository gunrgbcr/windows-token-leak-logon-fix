# Token-leak workaround: Windows sets the live ForegroundLockTimeout to 2147483647 at every logon.
# A new window is the foreground program, so Windows accepts the reset to 0 from here. Silent when already 0.
python "C:\path\to\flt_fix.py" --profile
