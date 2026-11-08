<?php
// ZS-PHP-015: HTTP_* server variables come straight from request headers.
header('Location: https://' . $_SERVER['HTTP_HOST'] . '/home');
