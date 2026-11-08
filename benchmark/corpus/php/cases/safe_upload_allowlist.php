<?php
// ZS-PHP-036 look-alike: extension allow-list check, then a generated name.
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (in_array($ext, ['jpg', 'png'], true)) {
    move_uploaded_file($_FILES['f']['tmp_name'], '/srv/uploads/' . $ext . '/' . $_FILES['f']['name']);
}
move_uploaded_file($_FILES['g']['tmp_name'], '/srv/uploads/' . bin2hex(random_bytes(16)));
