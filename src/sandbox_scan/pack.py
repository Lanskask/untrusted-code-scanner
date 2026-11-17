"""Pack the untrusted folder into a tar.gz, stripping dangerous modes."""

import os
import stat as _s
import tarfile
from pathlib import Path


def pack(src: Path, dest: Path, max_mb: int) -> int:
    total = 0
    with tarfile.open(dest, "w:gz") as tf:
        for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if not (_s.S_ISREG(st.st_mode) or _s.S_ISDIR(st.st_mode) or _s.S_ISLNK(st.st_mode)):
                    continue  # skip fifos, sockets, devices
                total += st.st_size if _s.S_ISREG(st.st_mode) else 0
                if total > max_mb * 1024 * 1024:
                    raise SystemExit(f"Codebase larger than {max_mb} MB; raise --max-mb or prune it.")
                ti = tf.gettarinfo(str(p), arcname=str(p.relative_to(src)))
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode &= 0o755  # drop setuid/setgid/sticky and group/world write
                if ti.isreg():
                    with open(p, "rb") as f:
                        tf.addfile(ti, f)
                else:
                    tf.addfile(ti)
    return total
