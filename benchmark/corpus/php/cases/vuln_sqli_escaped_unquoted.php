<?php
// ZS-PHP-002: a string escape does nothing for a value used without quotes.
$conn = mysqli_connect("localhost", "user", "pass", "db");
$id = mysqli_real_escape_string($conn, $_POST['id']);
$q = "SELECT * FROM users WHERE user_id = $id;";
mysqli_query($conn, $q);
