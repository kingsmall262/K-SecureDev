import os
# Juliet Test Suite v1.3 - CWE-78 OS Command Injection Sample 9

def query_host(ip_address):
    # Vulnerable: shell=True with unvalidated string input
    cmd = "nslookup " + ip_address
    os.system(cmd)

if __name__ == "__main__":
    ip = input("Enter host IP or hostname: ")
    query_host(ip)
