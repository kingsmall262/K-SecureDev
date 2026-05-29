import streamlit as st
import requests

API_URL = "http://localhost:8000/api/v1"

st.set_page_config(page_title="K-SecureDev 관제센터", page_icon="🛡️", layout="wide")

st.sidebar.title("⚡ K-SecureDev")
st.sidebar.markdown("---")
menu = st.sidebar.radio("통합 관제 메뉴 레이어", ["Dashboard Home", "K-Phishing Scanner", "Code Vulnerability Patch", "Admin History"])

if menu == "Dashboard Home" or menu == "Code Vulnerability Patch":
    st.title("🛡️ 실시간 분석 리포트")
    
    col_score, col_ind = st.columns([1, 2])
    with col_score:
        html_box = "<div style='background-color: #F3F4F6; padding: 20px; border-radius: 10px; border-left: 5px solid #EF4444; text-align: center;'>"
        html_box += "<h3 style='margin:0; color:#EF4444;'>RISK SCORE</h3>"
        html_box += "<h1 style='margin:0; font-size:64px;'>85</h1>"
        html_box += "<p style='margin:0; font-weight:bold; color:#DC2626;'>HIGH</p>"
        html_box += "</div>"
        st.markdown(html_box, unsafe_allow_html=True)
        
    with col_ind:
        st.markdown("<br><br>", unsafe_allowed_html=True)
        st.error("🔴 피싱 링크 탐지 | 🔴 SQL 인젝션 취약점 | 🔴 취약한 코드 발견")

    st.markdown("---")
    
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("📋 입력된 위협 데이터")
        default_code = "$user_input = $_GET['id'];\n$query = \"SELECT * FROM users WHERE id = \" . $user_input;\n$result = mysqli_query($conn, $query);"
        code_data = st.text_area("C / PHP 소스코드 입력 피드", value=default_code, height=200)
        btn_scan = st.button("🚀 정적 분석 및 Safe-Clone 요청")

    with c_right:
        st.subheader("🔒 Safe-Clone 제안")
        if btn_scan:
            with st.spinner("Joern CPG 컴파일 및 취약성 대조 알고리즘 수행 중..."):
                try:
                    res = requests.post(f"{API_URL}/code-analysis", json={"filename": "auth.php", "source_code": code_data})
                    if res.status_code == 200:
                        st.markdown(res.json()["ai_patch_guide"])
                except:
                    st.error("백엔드 서버(Port 8000) 구동 상태를 확인하세요.")
        else:
            st.caption("분석 실행 버튼을 누르면 패치 코드가 여기에 빌드됩니다.")

    st.markdown("---")
    cb1, cb2, _ = st.columns([1, 1, 3])
    with cb1: st.button("📋 패치 코드 복사하기")
    with cb2: st.button("📥 분석 리포트 PDF 저장")

elif menu == "K-Phishing Scanner":
    st.subheader("💬 한국어 특화 사칭 스미싱 스캐너")
    sms_data = st.text_area("SMS 문자 본문", value="[국민은행] 긴급: 비밀번호가 유출되었습니다. http://kb-bank.io/check_acct")
    if st.button("사회공학적 의도 판독"):
        try:
            res = requests.post(f"{API_URL}/smishing", json={"text": sms_data})
            if res.status_code == 200:
                st.json(res.json())
        except: 
            st.error("백엔드 서버 연동 실패")