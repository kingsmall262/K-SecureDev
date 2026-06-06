<?php
// Juliet Test Suite v1.3 - CWE-89 SQL Injection Sample 10
$conn = mysqli_connect("localhost", "db_user", "db_pass", "db_name");
$user_id = $_GET['id'];

// Vulnerable: raw user input concatenated directly into query
$query = "SELECT * FROM guests WHERE id = " . $user_id;
$result = mysqli_query($conn, $query);
while ($row = mysqli_fetch_assoc($result)) {
    echo "User: " . $row['username'] . "\n";
}
?>
