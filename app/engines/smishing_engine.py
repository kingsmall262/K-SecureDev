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
            'models/gemini-2.5-flash',
            generation_config={"response_mime_type": "application/json"}
        )
        
        # 3. 규칙 기반 엔진: 정규표현식으로 악성 의심 URL 사전 적출
        self.url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')

        # 4. KoBERT 모델 지연 로딩(Lazy Loading) 플래그 설정
        self.kobert_loaded = False
        self.kobert_tokenizer = None
        self.kobert_model = None

    def load_kobert(self) -> bool:
        if self.kobert_loaded:
            return True
        try:
            # transformers와 torch 모듈 임포트 시도
            from transformers import BertTokenizer, BertModel
            import torch
            
            # HuggingFace 허브로부터 monologg/kobert 모델과 토크나이저 연동
            self.kobert_tokenizer = BertTokenizer.from_pretrained("monologg/kobert")
            self.kobert_model = BertModel.from_pretrained("monologg/kobert")
            self.kobert_loaded = True
            logger.info("KoBERT 엔진이 성공적으로 로드되었습니다.")
            return True
        except Exception as e:
            logger.warning(f"KoBERT 로딩 실패 (Gemini/로컬 폴백 사용 예정): {str(e)}")
            return False

    def analyze_with_kobert(self, text: str) -> dict:
        import torch
        import numpy as np

        # 피싱 위협 카테고리별 기준 코어 문맥 사전
        REF_SENTENCES = {
            "부고 사칭": "부고 장례식장 알림 모바일 조문 위로금 전달 부친상 모친상",
            "택배 사칭": "배송 지연 주소지 오류 반송 상품 재배송 송장 번호 확인",
            "기관 사칭": "국민은행 금융 감독원 본인인증 계좌 인출 거래 정지 긴급 비밀번호 유출",
            "지인 사칭": "엄마 나 핸드폰 액정 깨졌어 문화상품권 대리 구매해줘 바빠 링크 클릭"
        }

        # 1. 입력 텍스트 토크나이징 및 임베딩 추출
        inputs = self.kobert_tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
        with torch.no_grad():
            outputs = self.kobert_model(**inputs)
        # CLS 토큰의 최종 히든 레이어 출력을 문장 임베딩 값으로 정의
        text_embedding = outputs.last_hidden_state[:, 0, :].squeeze(0).numpy()

        # 2. 각 스미싱 의심 범주와의 코사인 유사도 분석
        best_threat = "정상"
        max_sim = 0.0

        for threat, ref in REF_SENTENCES.items():
            ref_inputs = self.kobert_tokenizer(ref, return_tensors="pt", truncation=True, max_length=128)
            with torch.no_grad():
                ref_outputs = self.kobert_model(**ref_inputs)
            ref_embedding = ref_outputs.last_hidden_state[:, 0, :].squeeze(0).numpy()

            dot_product = np.dot(text_embedding, ref_embedding)
            norm_text = np.linalg.norm(text_embedding)
            norm_ref = np.linalg.norm(ref_embedding)
            similarity = dot_product / (norm_text * norm_ref)

            if similarity > max_sim:
                max_sim = similarity
                best_threat = threat

        # 코사인 유사도 임계값(Threshold) 매칭을 통한 위험성 판독
        if max_sim >= 0.70:
            is_phishing = True
            risk_score = int((max_sim - 0.70) / 0.30 * 50 + 50)
            risk_score = min(100, max(50, risk_score))
            reason = f"KoBERT 딥러닝 문맥 진단: '{best_threat}' 범주와 높은 임베딩 유사도({max_sim:.3f}) 포착."
        else:
            is_phishing = False
            risk_score = int(max_sim * 40)
            reason = f"KoBERT 분석 완료 (정상): 사회공학적 위험 문맥 유사도({max_sim:.3f})가 임계값 미만입니다."
            best_threat = "정상"

        return {
            "risk_score": risk_score,
            "is_phishing": is_phishing,
            "threat_type": best_threat,
            "reason": reason
        }

    def analyze_sms(self, text: str) -> dict:
        """
        유저가 입력한 SMS 텍스트를 분석하여 Dict 객체로 반환합니다.
        KoBERT 탐지를 우선 시도하고, 오프라인 또는 에러 시 Gemini API 및 룰베이스로 폴백합니다.
        """
        extracted_urls = self.url_pattern.findall(text)
        
        # 1. KoBERT 기반 문맥 분석 시도
        if self.load_kobert():
            try:
                ai_analysis = self.analyze_with_kobert(text)
                
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
                logger.error(f"KoBERT 임베딩 연산 중 오류 발생, Gemini 폴백 실행: {str(e)}")

        # 2. KoBERT 로드 실패 혹은 런타임 오류 시 Gemini 2.5 Flash API로 폴백
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
            
            # [API 오류 대비 로컬 룰베이스 예비 판독기 가동]
            suspicious_keywords = ["국민은행", "비밀번호", "유출", "긴급", "배송지", "배송", "지연", "택배", "본인인증", "인증", "부고", "결혼"]
            has_keyword = any(kw in text for kw in suspicious_keywords)
            
            # 악성 의심 키워드나 URL이 있는 경우 로컬 엔진에서 즉시 위험 판정
            if extracted_urls or has_keyword:
                fallback_score = 85 if (extracted_urls and has_keyword) else 65
                fallback_phishing = True
                fallback_threat = "사칭 의심"
                fallback_reason = f"로컬 위협 감지: 의심 징후(키워드/링크) 포착 (API 미동작: {str(e)[:35]}...)"
            else:
                fallback_score = 5
                fallback_phishing = False
                fallback_threat = "정상"
                fallback_reason = f"로컬 분석 정상: 특이 징후 없음 (API 미동작: {str(e)[:35]}...)"
                
            return {
                "status": "warning",
                "original_text": text,
                "extracted_urls": extracted_urls,
                "analysis_result": {
                    "risk_score": fallback_score,
                    "is_phishing": fallback_phishing,
                    "threat_type": fallback_threat,
                    "reason": fallback_reason
                }
            }

# 싱글톤 인스턴스 생성 및 main.py에서 임포트할 래퍼 함수 추가
_default_engine = SmishingEngine()

def analyze_smishing(text: str) -> dict:
    return _default_engine.analyze_sms(text)

if __name__ == "__main__":
    engine = SmishingEngine()
    test_text = "[웹발신] 구진서님, 주문하신 상품이 주소지 오류로 배송 지연중입니다. 아래 링크에서 확인바랍니다. http://bit.ly/fake-url"
    result = engine.analyze_sms(test_text)
    print(json.dumps(result, indent=4, ensure_ascii=False))