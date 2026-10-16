import shutil
import tempfile


def rmtree_logged(path):
    shutil.rmtree(path, ignore_errors=True)


def run_scan():
    workdir = tempfile.mkdtemp(prefix="scan-")
    try:
        return workdir
    finally:
        rmtree_logged(workdir)
