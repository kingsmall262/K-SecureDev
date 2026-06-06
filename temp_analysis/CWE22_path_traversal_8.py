import os
# Juliet Test Suite v1.3 - CWE-22 Path Traversal Sample 8

def read_user_file(file_name):
    # Vulnerable: directly joining user input allows directory traversal
    target_path = os.path.join("/var/www/data/backups", file_name)
    with open(target_path, "r") as f:
        return f.read()

if __name__ == "__main__":
    name = input("Enter filename: ")
    print(read_user_file(name))
