<?php
// Legacy search page, not routed through Laravel.
$db = mysqli_connect('localhost', 'app', getenv('DB_PASSWORD'), 'notes');
$q = $_GET['q'] ?? '';
$page = $_GET['page'] ?? 'results';

echo '<h2>Results for ' . $_GET['q'] . '</h2>';
echo '<p class="hint">Showing matches for ' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '</p>';

$result = mysqli_query($db, "SELECT title FROM notes WHERE title LIKE '%" . $_GET['q'] . "%'");
while ($row = mysqli_fetch_assoc($result)) {
    echo '<li>' . htmlspecialchars($row['title']) . '</li>';
}

$stmt = mysqli_prepare($db, 'SELECT title FROM notes WHERE owner = ?');
mysqli_stmt_bind_param($stmt, 's', $_GET['owner']);
mysqli_stmt_execute($stmt);

include 'partials/' . $page . '.php';
