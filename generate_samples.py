import os

JULIET_SAMPLE_DIR = "./juliet_samples"
os.makedirs(JULIET_SAMPLE_DIR, exist_ok=True)

# Templates for 5 CWE types
# 1. CWE-119: Buffer Overflow (C)
cwe119_vuln_template = """#include <stdio.h>
#include <string.h>

// Juliet Test Suite v1.3 - CWE-119 Buffer Overflow Sample {id}
void bad_func_{id}(char *src) {{
    char buffer[{buf_size}];
    // Vulnerable: unsafe strcpy may overflow buffer
    strcpy(buffer, src);
    printf("Content: %s\\n", buffer);
}}

int main(int argc, char **argv) {{
    if (argc > 1) {{
        bad_func_{id}(argv[1]);
    }}
    return 0;
}}
"""

cwe119_ref_template = """#include <stdio.h>
#include <string.h>

// Juliet Test Suite v1.3 - CWE-119 Buffer Overflow Reference {id}
void good_func_{id}(char *src) {{
    char buffer[{buf_size}];
    // Secure: using strncpy with size limit and null termination
    strncpy(buffer, src, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Content: %s\\n", buffer);
}}

int main(int argc, char **argv) {{
    if (argc > 1) {{
        good_func_{id}(argv[1]);
    }}
    return 0;
}}
"""

# 2. CWE-89: SQL Injection (PHP)
cwe89_vuln_template = """<?php
// Juliet Test Suite v1.3 - CWE-89 SQL Injection Sample {id}
$conn = mysqli_connect("localhost", "db_user", "db_pass", "db_name");
$user_id = $_GET['id'];

// Vulnerable: raw user input concatenated directly into query
$query = "SELECT * FROM {table_name} WHERE id = " . $user_id;
$result = mysqli_query($conn, $query);
while ($row = mysqli_fetch_assoc($result)) {{
    echo "User: " . $row['username'] . "\\n";
}}
?>
"""

cwe89_ref_template = """<?php
// Juliet Test Suite v1.3 - CWE-89 SQL Injection Reference {id}
$conn = mysqli_connect("localhost", "db_user", "db_pass", "db_name");
$user_id = (int)$_GET['id'];

// Secure: Prepared statement to prevent SQL Injection
$query = "SELECT * FROM {table_name} WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {{
    echo "User: " . $row['username'] . "\\n";
}}
?>
"""

# 3. CWE-79: Cross-Site Scripting (PHP)
cwe79_vuln_template = """<?php
// Juliet Test Suite v1.3 - CWE-79 Cross-Site Scripting Sample {id}
$user_input = $_POST['username'];

// Vulnerable: unescaped user input echoed back to browser
echo "<div class='profile'><h2>Welcome, " . $user_input . "</h2></div>";
?>
"""

cwe79_ref_template = """<?php
// Juliet Test Suite v1.3 - CWE-79 Cross-Site Scripting Reference {id}
$user_input = $_POST['username'];

// Secure: htmlspecialchars used to prevent XSS
$safe_input = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
echo "<div class='profile'><h2>Welcome, " . $safe_input . "</h2></div>";
?>
"""

# 4. CWE-22: Path Traversal (Python)
cwe22_vuln_template = """import os
# Juliet Test Suite v1.3 - CWE-22 Path Traversal Sample {id}

def read_user_file(file_name):
    # Vulnerable: directly joining user input allows directory traversal
    target_path = os.path.join("/var/www/data/{sub_dir}", file_name)
    with open(target_path, "r") as f:
        return f.read()

if __name__ == "__main__":
    name = input("Enter filename: ")
    print(read_user_file(name))
"""

cwe22_ref_template = """import os
# Juliet Test Suite v1.3 - CWE-22 Path Traversal Reference {id}

def read_user_file(file_name):
    base_directory = os.path.abspath("/var/www/data/{sub_dir}")
    target_path = os.path.abspath(os.path.join(base_directory, file_name))
    
    # Secure: Verify that target path resolves within base directory
    if target_path.startswith(base_directory):
        with open(target_path, "r") as f:
            return f.read()
    else:
        raise ValueError("Security violation: path traversal detected")

if __name__ == "__main__":
    name = input("Enter filename: ")
    print(read_user_file(name))
"""

# 5. CWE-78: OS Command Injection (Python)
cwe78_vuln_template = """import os
# Juliet Test Suite v1.3 - CWE-78 OS Command Injection Sample {id}

def query_host(ip_address):
    # Vulnerable: shell=True with unvalidated string input
    cmd = "nslookup " + ip_address
    os.system(cmd)

if __name__ == "__main__":
    ip = input("Enter host IP or hostname: ")
    query_host(ip)
"""

cwe78_ref_template = """import subprocess
# Juliet Test Suite v1.3 - CWE-78 OS Command Injection Reference {id}

def query_host(ip_address):
    # Secure: execution as a list prevents command injection
    subprocess.run(["nslookup", ip_address], check=True)

if __name__ == "__main__":
    ip = input("Enter host IP or hostname: ")
    query_host(ip)
"""

def main():
    print(f"Generating 50 mock Juliet Test Suite samples in '{JULIET_SAMPLE_DIR}'...")
    
    # Generate 10 samples for each CWE
    for i in range(1, 11):
        # 1. CWE-119 Buffer Overflow (C)
        buf_size = 8 + (i * 4) # Varying buffer sizes
        vuln_content = cwe119_vuln_template.format(id=i, buf_size=buf_size)
        ref_content = cwe119_ref_template.format(id=i, buf_size=buf_size)
        
        with open(os.path.join(JULIET_SAMPLE_DIR, f"CWE119_buffer_overflow_{i}.c"), "w", encoding="utf-8") as f:
            f.write(vuln_content)
        with open(os.path.join(JULIET_SAMPLE_DIR, f"secure_CWE119_buffer_overflow_{i}.c"), "w", encoding="utf-8") as f:
            f.write(ref_content)

        # 2. CWE-89 SQL Injection (PHP)
        table_names = ["users", "accounts", "customers", "employees", "admins", "members", "leads", "vendors", "students", "guests"]
        table_name = table_names[i - 1]
        vuln_content = cwe89_vuln_template.format(id=i, table_name=table_name)
        ref_content = cwe89_ref_template.format(id=i, table_name=table_name)
        
        with open(os.path.join(JULIET_SAMPLE_DIR, f"CWE89_sql_injection_{i}.php"), "w", encoding="utf-8") as f:
            f.write(vuln_content)
        with open(os.path.join(JULIET_SAMPLE_DIR, f"secure_CWE89_sql_injection_{i}.php"), "w", encoding="utf-8") as f:
            f.write(ref_content)

        # 3. CWE-79 XSS (PHP)
        vuln_content = cwe79_vuln_template.format(id=i)
        ref_content = cwe79_ref_template.format(id=i)
        
        with open(os.path.join(JULIET_SAMPLE_DIR, f"CWE79_xss_{i}.php"), "w", encoding="utf-8") as f:
            f.write(vuln_content)
        with open(os.path.join(JULIET_SAMPLE_DIR, f"secure_CWE79_xss_{i}.php"), "w", encoding="utf-8") as f:
            f.write(ref_content)

        # 4. CWE-22 Path Traversal (Python)
        sub_dirs = ["uploads", "downloads", "documents", "reports", "images", "videos", "logs", "backups", "configs", "receipts"]
        sub_dir = sub_dirs[i - 1]
        vuln_content = cwe22_vuln_template.format(id=i, sub_dir=sub_dir)
        ref_content = cwe22_ref_template.format(id=i, sub_dir=sub_dir)
        
        with open(os.path.join(JULIET_SAMPLE_DIR, f"CWE22_path_traversal_{i}.py"), "w", encoding="utf-8") as f:
            f.write(vuln_content)
        with open(os.path.join(JULIET_SAMPLE_DIR, f"secure_CWE22_path_traversal_{i}.py"), "w", encoding="utf-8") as f:
            f.write(ref_content)

        # 5. CWE-78 OS Command Injection (Python)
        vuln_content = cwe78_vuln_template.format(id=i)
        ref_content = cwe78_ref_template.format(id=i)
        
        with open(os.path.join(JULIET_SAMPLE_DIR, f"CWE78_command_injection_{i}.py"), "w", encoding="utf-8") as f:
            f.write(vuln_content)
        with open(os.path.join(JULIET_SAMPLE_DIR, f"secure_CWE78_command_injection_{i}.py"), "w", encoding="utf-8") as f:
            f.write(ref_content)

    print(f"Successfully generated 50 vulnerable/secure sample pairs in '{JULIET_SAMPLE_DIR}'!")

if __name__ == "__main__":
    main()
