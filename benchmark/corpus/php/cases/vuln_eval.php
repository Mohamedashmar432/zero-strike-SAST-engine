<?php
$expr = $_GET['expr'];
// ZS-PHP-018: eval() executes attacker-controlled PHP code
eval($expr);
