# nx2elf
Convert Nintendo Switch executable files to ELFs

# Known Issues
1. Does not handle 32bit files.
1. Input files contain 3 segments, divided by memory protection type. This tool attempts to derive original ELF sections which were merged into these 3 segments. For simplicity, this currently results in sections which overlap the main 3 segments, since they reside within their bounds. Tools like IDA will complain about this, but it shouldn't actually result in any problems. File an issue if it does.
