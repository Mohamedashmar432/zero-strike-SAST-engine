<?php
// ZS-PHP-009: SQL injection — query built by concatenating tainted $id
$conn = pg_connect("host=localhost dbname=db user=user password=pass");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
pg_query($conn, $query);
