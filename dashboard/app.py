import streamlit as st
import requests
from datetime import datetime
from fpdf import FPDF
import json
import os
import pandas as pd

# API 서버 주소 및 히스토리 파일 경로
API_URL = "http://127.0.0.1:8000/api/v1/scan"
HISTORY_FILE = "dashboard/history.json"

# --- 데이터베이스(JSON) 제어 함수 ---
def load_history():
    """JSON 파일에서 스캔 히스토리 불러오기"""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_history(record):
    """새로운 스캔 기록을 JSON 파일에 누적 저장하기"""
    history = load_history()
    history.append(record)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=4)

def create_pdf_report(scan_result):
    """분석 리포트 PDF 생성기"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="K-SecureDev AI Smishing Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(200, 10, txt=f"Risk Score: {scan_result['analysis_result']['risk_score']} / 100", ln=True)
    pdf.cell(200, 10, txt=f"Is Phishing: {scan_result['analysis_result']['is_phishing']}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Analysis Reason:\n{scan_result['analysis_result']['reason']}")
    return pdf.output(dest='S').encode('latin1')

# --- 프론트엔드 UI 구성 ---
st.set_page_config(page_title="K-SecureDev", page_icon="🛡️", layout="wide")
st.title("🛡️ K-SecureDev Dashboard")

tab1, tab2, tab3 = st.tabs(["📲 K-Phishing Scanner", "💻 Safe-Clone Code", "⚙️ Admin History"])

with tab1:
    st.subheader("스미싱 / 사회공학적 위협 탐지")
    user_sms = st.text_area("의심스러운 문자 메시지 본문을 입력하세요:", height=150)
    
    if st.button("스캔 시작", type="primary"):
        if not user_sms.strip():
            st.warning("분석할 텍스트를 입력해주세요.")
        else:
            with st.spinner("AI 엔진 분석 중... (API Gateway 호출)"):
                try:
                    response = requests.post(API_URL, json={"text": user_sms})
                    
                    if response.status_code == 200:
                        result = response.json()
                        score = result['analysis_result']['risk_score']
                        is_phishing = result['analysis_result']['is_phishing']
                        threat_type = result['analysis_result'].get('threat_type', 'Unknown')
                        
                        # --- 1. 화면 출력 로직 ---
                        if is_phishing:
                            st.error(f"⚠️ 위험! (Risk Score: {score}) - {threat_type}")
                        else:
                            st.success(f"✅ 안전한 메시지입니다. (Risk Score: {score})")
                            
                        st.info(f"💡 AI 분석 의견: {result['analysis_result']['reason']}")
                        
                        if result.get('extracted_urls'):
                            st.warning(f"🔗 추출된 의심 URL: {', '.join(result['extracted_urls'])}")

                        # --- 2. Admin History에 데이터 저장 ---
                        scan_record = {
                            "Scan Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "Message Snippet": user_sms[:20] + "..." if len(user_sms) > 20 else user_sms,
                            "Risk Score": score,
                            "Is Phishing": "⚠️ 위험" if is_phishing else "✅ 안전",
                            "Threat Type": threat_type
                        }
                        save_history(scan_record)

                        # --- 3. PDF 다운로드 ---
                        pdf_bytes = create_pdf_report(result)
                        st.download_button(
                            label="📥 분석 리포트 PDF 저장",
                            data=pdf_bytes,
                            file_name=f"ksecure_report_{datetime.now().strftime('%Y%m%d%H%M')}.pdf",
                            mime="application/pdf"
                        )
                    else:
                        st.error(f"서버 에러 발생: HTTP {response.status_code}")
                
                except requests.exceptions.ConnectionError:
                    st.error("🚨 백엔드 API 서버(FastAPI)와 연결할 수 없습니다. 8000번 포트 서버가 켜져 있는지 확인하세요.")

with tab2:
    st.subheader("Safe-Clone Code Viewer")
    st.markdown("유저가 제미나이가 뱉어낸 명품 Safe-Clone 코드를 원클릭으로 복사할 수 있습니다.")
    sample_safe_code = """import hashlib

def secure_login(username, password):
    salt = "k_secure_dev_salt"
    hashed_pw = hashlib.sha256((password + salt).encode()).hexdigest()
    return db.verify(username, hashed_pw)
"""
    st.code(sample_safe_code, language='python')

with tab3:
    st.subheader("Admin History")
    st.markdown("사용자들의 스미싱 탐지 이력을 모니터링하는 관리자 패널입니다.")
    
    # 누적된 히스토리 데이터 불러오기
    history_data = load_history()
    
    if history_data:
        # 데이터를 Pandas 데이터프레임으로 변환
        df = pd.DataFrame(history_data)
        
        # 최신 스캔 기록이 맨 위로 오도록 역순 정렬
        df = df.iloc[::-1].reset_index(drop=True)
        
        # 화면에 꽉 차는 예쁜 표로 렌더링
        st.dataframe(df, use_container_width=True)
    else:
        st.info("아직 누적된 스캔 이력이 없습니다. 'K-Phishing Scanner' 탭에서 문자를 스캔해 보세요!")
