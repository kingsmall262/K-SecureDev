from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
from app.engines.smishing_engine import analyze_smishing
from app.engines.code_engine import analyze_code_clone

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
        return analyze_code_clone(payload.filename, payload.source_code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))