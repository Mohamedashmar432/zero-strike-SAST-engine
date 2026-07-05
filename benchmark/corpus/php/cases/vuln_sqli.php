<?php
// ZS-PHP-002: SQL injection — query built by concatenating tainted $id
$conn = mysqli_connect("localhost", "user", "pass", "db");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $query);
