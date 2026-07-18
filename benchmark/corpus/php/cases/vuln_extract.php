<?php
// ZS-PHP-022: extract() on a request superglobal lets an attacker
// overwrite arbitrary local variables (mass assignment)
extract($_POST);
