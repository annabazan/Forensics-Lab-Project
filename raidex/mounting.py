"""EWF image mounting via ewfmount (read-only FUSE)."""

from __future__ import annotations

import logging
import os
import tempfile

from raidex.util import run

logger = logging.getLogger(__name__)


class EwfMount:
    """Context manager to mount an E01 image via ewfmount."""

    def __init__(self, e01_path: str) -> None:
        self.e01_path = e01_path
        self.mountpoint: str | None = None

    def __enter__(self) -> str:
        self.mountpoint = tempfile.mkdtemp(prefix="ewf_")
        rc, _, err = run(["ewfmount", self.e01_path, self.mountpoint])
        if rc != 0:
            os.rmdir(self.mountpoint)
            raise RuntimeError(
                f"ewfmount failed for {self.e01_path}: {err.decode()}"
            )
        return os.path.join(self.mountpoint, "ewf1")

    def __exit__(self, *exc: object) -> None:
        if self.mountpoint:
            run(["fusermount", "-u", self.mountpoint])
            try:
                os.rmdir(self.mountpoint)
            except OSError:
                pass
