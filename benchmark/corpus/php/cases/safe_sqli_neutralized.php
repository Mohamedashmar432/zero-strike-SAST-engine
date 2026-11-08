<?php
// ZS-PHP-002 look-alike: integer cast, and an escaped value used only between quotes.
$conn = mysqli_connect("localhost", "user", "pass", "db");
$id = (int) $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$page = intval($_GET['page']);
mysqli_query($conn, "SELECT * FROM posts LIMIT 10 OFFSET $page");
$name = mysqli_real_escape_string($conn, $_POST['name']);
$q = "SELECT * FROM users WHERE name = '$name'";
mysqli_query($conn, $q);
$token = hash('sha256', $_POST['token']);
mysqli_query($conn, "SELECT * FROM sessions WHERE token = '" . $token . "'");
