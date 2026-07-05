<?php
// ZS-PHP-003: insecure deserialization — any use of unserialize() on
// untrusted data risks PHP object injection
$data = $_POST['payload'];
$obj = unserialize($data);
