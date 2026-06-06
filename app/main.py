import sys
import os

# .env 파일이 존재하는 경우 로컬 환경 변수로 수동 로드
_env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if os.path.exists(_env_path):
    with open(_env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

from typing import List
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# 모듈 경로 인식 문제 해결
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.smishing_engine import analyze_smishing
from app.engines.code_engine import analyze_code_clone
from app.engines.history_db import add_history, get_history, delete_history, clear_all_history

# FastAPI 앱 초기화
app = FastAPI(
    title="K-SecureDev Phishing API Gateway",
    description="비동기 기반 스미싱/피싱/코드 취약점 탐지 통합 백엔드 서버"
)

# CORS 미들웨어 적용 (민욱 팀원 소스)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 프론트엔드 통신 데이터 규격(Pydantic) 정의
class SmishingRequest(BaseModel):
    text: str

class SmishingResponse(BaseModel):
    status: str
    analysis_result: dict
    extracted_urls: List[str] = []

class CodeAnalysisRequest(BaseModel):
    filename: str
    source_code: str

class CodeAnalysisResponse(BaseModel):
    filename: str
    vulnerable_clone_found: bool
    matched_cve: str
    risk_score: int
    vulnerability_details: str
    ai_patch_guide: str

# 1. 헬스 체크 엔드포인트
@app.get("/health")
def health_check():
    return {"status": "green", "message": "Backend gateway is alive"}

# 2. 스미싱 탐지 엔드포인트
@app.post("/api/v1/smishing", response_model=SmishingResponse)
def endpoint_smishing(payload: SmishingRequest):
    try:
        return analyze_smishing(payload.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3. 코드 정적 분석 및 취약점 패치 엔드포인트 (add_history 자동 결합)
@app.post("/api/v1/code-analysis", response_model=CodeAnalysisResponse)
def endpoint_code(payload: CodeAnalysisRequest):
    try:
        result = analyze_code_clone(payload.filename, payload.source_code)
        # 스캔 이력을 DB에 기록
        add_history(
            filename=result["filename"],
            cwe=result["matched_cve"],
            risk_score=result["risk_score"],
            vulnerable=result["vulnerable_clone_found"],
            details=result["vulnerability_details"]
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 4. 탐지 이력 전체 조회 엔드포인트
@app.get("/api/v1/history")
def endpoint_get_history():
    try:
        return get_history()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 5. 탐지 이력 선택 삭제 엔드포인트
@app.delete("/api/v1/history/{record_id}")
def endpoint_delete_history(record_id: int):
    try:
        delete_history(record_id)
        return {"status": "success", "message": f"Record {record_id} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 6. 전체 이력 초기화 엔드포인트
@app.post("/api/v1/history/clear")
def endpoint_clear_history():
    try:
        clear_all_history()
        return {"status": "success", "message": "All history cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))