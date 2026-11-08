<?php
// ZS-PHP-036: the upload lands under the client-supplied file name.
$target = '/var/www/html/uploads/' . basename($_FILES['f']['name']);
move_uploaded_file($_FILES['f']['tmp_name'], $target);
