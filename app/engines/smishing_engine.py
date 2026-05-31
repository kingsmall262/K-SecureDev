import re
import json
import os
import google.generativeai as genai
import logging

logger = logging.getLogger(__name__)

class SmishingEngine:
    def __init__(self):
        # 1. 환경 변수에서 API 키 로드 (보안 실무의 기본)
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("GEMINI_API_KEY가 설정되지 않았습니다. API 연동에 실패할 수 있습니다.")
        else:
            genai.configure(api_key=api_key)
            
        # 2. Gemini 최신 2.5 Flash 모델 세팅 (JSON 응답 강제 옵션 유지)
        self.model = genai.GenerativeModel(
            'models/gemini-2.5-flash',  # <--- 이 부분을 2.5 버전으로 완벽히 수정!
            generation_config={"response_mime_type": "application/json"}
        )
        
        # 3. 규칙 기반 엔진: 정규표현식으로 악성 의심 URL 사전 적출
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')

    def analyze_sms(self, text: str) -> dict:
        """
        유저가 입력한 SMS 텍스트를 분석하여 Dict 객체로 반환합니다.
        (프론트엔드로 전달될 판독 데이터 객체)
        """
        extracted_urls = self.url_pattern.findall(text)
        
        prompt = f"""
        당신은 한국의 사이버 보안 전문가이자 스미싱 탐지 AI입니다.
        다음은 사용자가 수신한 SMS 메시지입니다. 이 메시지의 사회공학적 낚시 의도와 스미싱 여부를 분석하세요.
        반드시 아래의 JSON 포맷으로만 응답해야 합니다.

        {{
            "risk_score": 0~100 사이의 정수 (위험도 점수),
            "is_phishing": true 또는 false,
            "threat_type": "부고 사칭", "택배 사칭", "기관 사칭", "지인 사칭", "정상" 중 택 1,
            "reason": "판단에 대한 1~2줄의 명확한 이유"
        }}
        
        SMS 내용: "{text}"
        """
        
        try:
            response = self.model.generate_content(prompt)
            ai_analysis = json.loads(response.text)
            
            # [규칙 기반 보정 로직]
            if extracted_urls and ai_analysis["risk_score"] < 40:
                ai_analysis["risk_score"] += 30
                ai_analysis["reason"] += " (주의: 알 수 없는 URL이 포함되어 있어 위험도가 상향 조정되었습니다.)"
                if ai_analysis["risk_score"] >= 60:
                    ai_analysis["is_phishing"] = True
                    
            return {
                "status": "success",
                "original_text": text,
                "extracted_urls": extracted_urls,
                "analysis_result": ai_analysis
            }
            
        except Exception as e:
            logger.error(f"AI 엔진 분석 중 에러 발생: {str(e)}")
            return {
                "status": "error",
                "original_text": text,
                "extracted_urls": extracted_urls,
                "analysis_result": {
                    "risk_score": 0,
                    "is_phishing": False,
                    "threat_type": "알 수 없음",
                    "reason": f"엔진 통신 오류: {str(e)}"
                }
            }

if __name__ == "__main__":
    engine = SmishingEngine()
    test_text = "[웹발신] 구진서님, 주문하신 상품이 주소지 오류로 배송 지연중입니다. 아래 링크에서 확인바랍니다. http://bit.ly/fake-url"
    result = engine.analyze_sms(test_text)
    print(json.dumps(result, indent=4, ensure_ascii=False))