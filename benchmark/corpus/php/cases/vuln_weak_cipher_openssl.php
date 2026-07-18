<?php
$plaintext = "customer record";
// ZS-PHP-026: openssl_encrypt() with the weak 3DES cipher
$ciphertext = openssl_encrypt($plaintext, 'des-ede3', $enc_key, 0, $iv);
