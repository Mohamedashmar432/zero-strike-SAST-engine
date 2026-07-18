# ZS-PY-045: extractall on an uploaded tarball, member paths not validated
import tarfile

tar = tarfile.open("upload.tar.gz")
tar.extractall("/srv/data")
