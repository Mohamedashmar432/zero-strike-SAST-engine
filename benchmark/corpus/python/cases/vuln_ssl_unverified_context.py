# ZS-PY-051: unverified SSL context accepts any certificate
import ssl

ctx = ssl._create_unverified_context()
