from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
from app.engines.smishing_engine import analyze_smishing
from app.engines.code_engine import analyze_code_clone
from app.engines.history_db import add_history, get_history, delete_history, clear_all_history

app = FastAPI(
    title="K-SecureDev Core Gateway",
    description="한국형 위협 대응 통합 백엔드 API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SmishingRequest(BaseModel):
    text: str = Field(..., min_length=1)

class SmishingResponse(BaseModel):
    input_text: str
    extracted_urls: List[str]
    nlp_confidence: float
    url_malicious: bool
    final_risk_score: float
    status: str

class CodeAnalysisRequest(BaseModel):
    filename: str
    source_code: str = Field(..., min_length=5)

class CodeAnalysisResponse(BaseModel):
    filename: str
    vulnerable_clone_found: bool
    matched_cve: str
    vulnerability_details: str
    ai_patch_guide: str

@app.get("/health")
def health_check():
    return {"status": "green", "message": "Backend gateway is alive"}

@app.post("/api/v1/smishing", response_model=SmishingResponse)
def endpoint_smishing(payload: SmishingRequest):
    try:
        return analyze_smishing(payload.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

@app.get("/api/v1/history")
def endpoint_get_history():
    try:
        return get_history()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/history/{record_id}")
def endpoint_delete_history(record_id: int):
    try:
        delete_history(record_id)
        return {"status": "success", "message": f"Record {record_id} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/history/clear")
def endpoint_clear_history():
    try:
        clear_all_history()
        return {"status": "success", "message": "All history cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))