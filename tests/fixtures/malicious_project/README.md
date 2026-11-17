# malicious_project (INERT test fixture)

Every file here only *looks* like an attack so that the scanner has something to find. All hosts end in `.invalid`
(they never resolve), nothing is ever run, and the e2e test only reads the folder.
**Never open this folder in an IDE with workspace trust, and never run anything in it.**
Items git or recursive tools should not hold (a symlink to `/etc`, `.git/hooks`, `.git/config`, an ELF in `node_modules/.bin`, Trojan Source characters) are
added by `tests/conftest.py::malicious_project`.
