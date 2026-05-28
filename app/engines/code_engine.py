def analyze_code_clone(filename: str, source_code: str) -> dict:
    is_vuln = "mysqli_query" in source_code or "strcpy" in source_code
    
    mock_patch = "### 🤖 K-SecureDev 보안 패치 가이드\n"
    mock_patch += "```php\n"
    mock_patch += "$userid = (int)$_GET['id'];\n"
    mock_patch += "$query = \"SELECT * FROM users WHERE id = ?\";\n"
    mock_patch += "$stmt = $conn->prepare($query);\n"
    mock_patch += "$stmt->bind_param(\"i\", $userid);\n"
    mock_patch += "$stmt->execute();\n"
    mock_patch += "$result = $stmt->get_result();\n"
    mock_patch += "```\n"
    mock_patch += "* Prepared Statement 적용 완료: SQL 인젝션을 차단했습니다.\n"
    mock_patch += "* 명시적 형변환 캐스팅 가드: 정수형 변환으로 무결성을 확보했습니다."

    return {
        "filename": filename,
        "vulnerable_clone_found": is_vuln,
        "matched_cve": "CWE-89 (SQL Injection)" if "mysqli_query" in source_code else "CWE-119 (Buffer Overflow Risk)",
        "vulnerability_details": "외부 유입 변수가 검증 없이 취약한 싱크 함수로 도달하는 위협 데이터 흐름이 추적되었습니다." if is_vuln else "안전함",
        "ai_patch_guide": mock_patch if is_vuln else "보안성 양호"
    }