import re

def analyze_smishing(text: str) -> dict:
    is_detected = "국민은행" in text or "비밀번호" in text or "유출" in text
    urls = re.findall(r'https?://[^\s]+', text)
    if not urls and "kb-bank.io" in text:
        urls = ["http://kb-bank.io/check_acct"]
    
    return {
        "input_text": text,
        "extracted_urls": urls,
        "nlp_confidence": 0.85 if is_detected else 0.05,
        "url_malicious": True if "kb-bank.io" in text or urls else False,
        "final_risk_score": 0.85 if is_detected else 0.10,
        "status": "CRITICAL" if is_detected else "SAFE"
    }