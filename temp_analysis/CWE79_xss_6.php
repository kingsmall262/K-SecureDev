<?php
// Juliet Test Suite v1.3 - CWE-79 Cross-Site Scripting Sample 6
$user_input = $_POST['username'];

// Vulnerable: unescaped user input echoed back to browser
echo "<div class='profile'><h2>Welcome, " . $user_input . "</h2></div>";
?>
