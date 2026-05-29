from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import logging
import sys
import os

# 모듈 경로 인식 문제 해결
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__name__))))
from app.engines.smishing_engine import SmishingEngine

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI 앱 초기화
app = FastAPI(
    title="K-SecureDev Phishing API Gateway",
    description="비동기 기반 스미싱/피싱 탐지 백엔드 서버"
)

# 서버 시작 시 엔진 로드
try:
    engine = SmishingEngine()
    logger.info("SmishingEngine 로드 성공. AI 분석 준비 완료.")
except Exception as e:
    logger.error(f"엔진 초기화 실패: {str(e)}")
    raise RuntimeError("서버 엔진 초기화에 실패했습니다.")

# 프론트엔드에서 날아올 데이터 규격(Pydantic)
class ScanRequest(BaseModel):
    text: str

# API 엔드포인트
@app.post("/api/v1/scan")
async def scan_message(request: ScanRequest):
    """프론트엔드에서 전송된 텍스트를 AI로 분석 후 반환"""
    if not request.text or not request.text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="분석할 텍스트가 제공되지 않았습니다."
        )
    
    # 엔진 호출 및 결과 리턴
    result = engine.analyze_sms(request.text)
    
    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["analysis_result"]["reason"]
        )
        
    return result

# 헬스 체크용
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "K-SecureDev API Server is running."}