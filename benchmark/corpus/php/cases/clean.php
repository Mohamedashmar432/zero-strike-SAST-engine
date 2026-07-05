<?php
// Negative fixture: none of the ZS-PHP rules should fire here.
$greeting = "hello";
echo htmlspecialchars($greeting);

system("ls -la");

$conn = mysqli_connect("localhost", "user", "pass", "db");
mysqli_query($conn, "SELECT 1");

$data = json_decode('{"a":1}', true);
