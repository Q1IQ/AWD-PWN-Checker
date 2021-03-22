# AWD-PWN-Checker
Description: A tool designed for checking the validity of patches made by participants in CTF AWD competitions. Helps ensure a fair competition by ensuring that patches made by participants are valid and in accordance with the rules. The checker uses SSH public key authentication to access the participant's server and verifies the binary file.


## Features

- Does not rely on the `pwntools` library.
- Detect if the patch changes `free` to `nop` or any other instruction.
- Detect if the patch increases the size of malloc
- Detect if the patch modifies the plt and got tables.

## Usage
```
python3 main.py pwncheck.py --host 1.2.3.4 --port 9999
```

## Ref
https://q1iq.top/awd-pwn-checker/
