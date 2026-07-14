<?php
// ZS-PHP-011: weak PRNG — mt_rand() used to generate a password-reset token
$resetToken = mt_rand();
