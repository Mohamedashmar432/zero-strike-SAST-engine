<?php
// ZS-PHP-002: a script under public/ is the web root of a PHP app, not a static asset.
$db = mysqli_connect("localhost", "app", getenv("DB_PASSWORD"), "notes");
$result = mysqli_query($db, "SELECT title FROM notes WHERE title LIKE %" . $_GET["q"] . "%");
