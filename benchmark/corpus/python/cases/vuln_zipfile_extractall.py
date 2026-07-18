# ZS-PY-046: extractall on an uploaded zip, member names not validated
import zipfile

zip_ref = zipfile.ZipFile("upload.zip", "r")
zip_ref.extractall("/srv/data")
