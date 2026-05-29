import streamlit as st
import requests
from datetime import datetime
from fpdf import FPDF
import json

# API 서버 주소 (FastAPI)
API_URL = "http://127.0.0.1:8000/api/v1/scan"

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
            with st.spinner("서버와 통신 중입니다... (API Gateway 호출)"):
                try:
                    # 1. FastAPI 서버로 HTTP POST 요청을 보냄
                    response = requests.post(API_URL, json={"text": user_sms})
                    
                    # 2. 통신 성공 시
                    if response.status_code == 200:
                        result = response.json()
                        score = result['analysis_result']['risk_score']
                        
                        if result['analysis_result']['is_phishing']:
                            st.error(f"⚠️ 위험! (Risk Score: {score}) - {result['analysis_result']['threat_type']}")
                        else:
                            st.success(f"✅ 안전한 메시지입니다. (Risk Score: {score})")
                            
                        st.info(f"💡 AI 분석 의견: {result['analysis_result']['reason']}")
                        
                        if result['extracted_urls']:
                            st.warning(f"🔗 추출된 의심 URL: {', '.join(result['extracted_urls'])}")

                        # PDF 다운로드
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
    sample_safe_code = """
import hashlib

def secure_login(username, password):
    salt = "k_secure_dev_salt"
    hashed_pw = hashlib.sha256((password + salt).encode()).hexdigest()
    return db.verify(username, hashed_pw)
"""
    st.code(sample_safe_code, language='python')

with tab3:
    st.subheader("Admin History")
    st.info("차후 SQLite 또는 JSON DB 연동 후 표기될 영역입니다.")