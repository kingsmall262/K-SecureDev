import streamlit as st
import requests
import re
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from pdf_generator import generate_pdf_report, generate_smishing_pdf_report
API_URL = "http://localhost:8000/api/v1"

# 대시보드 테마 설정 및 페이지 구성
st.set_page_config(page_title="K-SecureDev 관제센터", page_icon="🛡️", layout="wide")

# 세션 상태 초기화
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "risk_score" not in st.session_state:
    st.session_state.risk_score = 0
if "risk_status" not in st.session_state:
    st.session_state.risk_status = "CLEAN"
if "risk_color" not in st.session_state:
    st.session_state.risk_color = "#10B981"
if "filename" not in st.session_state:
    st.session_state.filename = "auth.php"
if "matched_cve" not in st.session_state:
    st.session_state.matched_cve = "N/A"
if "vulnerability_details" not in st.session_state:
    st.session_state.vulnerability_details = ""

# SMS 스캐너 상태 관리 변수 추가
if "sms_analysis_result" not in st.session_state:
    st.session_state.sms_analysis_result = None
if "sms_risk_score" not in st.session_state:
    st.session_state.sms_risk_score = 0
if "sms_risk_status" not in st.session_state:
    st.session_state.sms_risk_status = "CLEAN"
if "sms_risk_color" not in st.session_state:
    st.session_state.sms_risk_color = "#10B981"
if "sms_threat_type" not in st.session_state:
    st.session_state.sms_threat_type = "정상"
if "sms_reason" not in st.session_state:
    st.session_state.sms_reason = ""
if "sms_extracted_urls" not in st.session_state:
    st.session_state.sms_extracted_urls = []
if "sms_text" not in st.session_state:
    st.session_state.sms_text = ""

# 클립보드 복사를 위한 마크다운 내 코드 추출 헬퍼 함수
def extract_code_block(markdown_text: str) -> str:
    if not markdown_text:
        return ""
    code_match = re.search(r'```(?:[\w]*)\n(.*?)\n```', markdown_text, re.DOTALL)
    if code_match:
        return code_match.group(1)
    return markdown_text

# Javascript 클립보드 복사 컴포넌트 렌더러
def render_copy_button(text_to_copy: str):
    escaped_text = (
        text_to_copy.replace('\\', '\\\\')
        .replace('`', '\\`')
        .replace('$', '\\$')
        .replace('\n', '\\n')
        .replace('"', '\\"')
    )
    js_code = f"""
    <button id="btn-copy" style="
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background-color: #2563EB;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
        font-weight: 500;
        border-radius: 0.375rem;
        cursor: pointer;
        font-family: ui-sans-serif, system-ui, sans-serif;
        transition: background-color 0.2s;
        width: 100%%;
        height: 38px;
    ">
        패치 코드 복사
    </button>
    <div id="status" style="
        color: #10B981; 
        font-size: 0.75rem; 
        margin-top: 4px; 
        text-align: center; 
        font-family: sans-serif; 
        display: none;
        font-weight: bold;
    ">복사 완료</div>
    <script>
    document.getElementById('btn-copy').addEventListener('click', function() {{
        const text = "{escaped_text}";
        navigator.clipboard.writeText(text).then(() => {{
            const status = document.getElementById('status');
            status.style.display = 'block';
            setTimeout(() => {{ status.style.display = 'none'; }}, 2000);
        }}).catch(err => {{
            const textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {{
                document.execCommand('copy');
                const status = document.getElementById('status');
                status.style.display = 'block';
                setTimeout(() => {{ status.style.display = 'none'; }}, 2000);
            }} catch (e) {{
                alert('클립보드 복사에 실패했습니다. 수동으로 복사해주세요.');
            }}
            document.body.removeChild(textArea);
        }});
    }});
    </script>
    """
    st.components.v1.html(js_code, height=65)

# 사이드바 레이아웃 (정제된 엔터프라이즈 느낌으로 변경)
st.sidebar.markdown("<h2 style='margin-bottom:0px; font-weight:700; color:#FFFFFF;'>K-SecureDev</h2>", unsafe_allow_html=True)
st.sidebar.markdown("<p style='font-size:12px; color:#64748B;'>통합 보안 관제 시스템</p>", unsafe_allow_html=True)
st.sidebar.markdown("---")
menu = st.sidebar.radio("관제 메뉴 선택", ["Dashboard Home", "K-Phishing Scanner", "Code Vulnerability Patch", "Admin History"])

if menu == "Dashboard Home":
    st.title("K-SecureDev 통합 보안 관제 포털")
    st.markdown("한국형 사회공학적 피싱 탐지 및 프로그램 데이터 흐름(CPG) 정적 분석 통합 관리 대시보드")
    st.markdown("---")
    
    # 웰컴 배너 및 핵심 설명 (세련된 기업용 레이아웃)
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%); padding: 30px; border-radius: 12px; color: white; margin-bottom: 25px; border-left: 5px solid #2563EB;">
            <h2 style="margin: 0; font-size: 26px; font-weight: 700; color: #F8FAFC;">보안 분석 요약 및 프레임워크 개요</h2>
            <p style="margin: 12px 0 0 0; font-size: 14.5px; opacity: 0.9; line-height: 1.6; color: #CBD5E1;">
                K-SecureDev는 국내 사회공학적 사칭 문맥을 인지하는 <b>한국어 특화 탐지 엔진(KoBERT)</b>과, 소스코드의 비검증 데이터 흐름을 추적하는 <b>정적 분석 엔진(Joern CPG)</b>, 그리고 탐지된 취약점에 대해 시스템 호환성(CodeBLEU 0.85 이상)을 유지하며 교정하는 <b>AI Safe-Clone 모델(Gemini)</b>이 결합된 통합 위협 대응 솔루션입니다.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # 핵심 3대 보안 레이어 기능 소개 카드
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            """
            <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 190px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 15px; font-weight:700; border-bottom: 2px solid #EFF6FF; padding-bottom: 8px;">K-Phishing Scanner</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5; margin-top: 10px;">한국어 문장 형태와 미묘한 어미 차이를 심층 판독하여 신종 사회공학적 스미싱 공격을 실시간 감지합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #2563EB;">사이드바 [K-Phishing Scanner] 탭 사용</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            """
            <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 190px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 15px; font-weight:700; border-bottom: 2px solid #EFF6FF; padding-bottom: 8px;">Joern CPG Engine</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5; margin-top: 10px;">코드의 비검증 입력 데이터가 위험 함수(strcpy, query 등)로 유입되는 소스-싱크 흐름을 전적 정적 그래프(CPG)로 정밀 진단합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #2563EB;">사이드바 [Code Vulnerability Patch] 탭 사용</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            """
            <div style="background-color: #FFFFFF; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 190px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 15px; font-weight:700; border-bottom: 2px solid #EFF6FF; padding-bottom: 8px;">Gemini AI Safe-Patch</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5; margin-top: 10px;">정밀 진단된 보안 결함 데이터를 참조하여, 기존 비즈니스 기능을 훼손하지 않는 안전한 대체 코드(Safe-Clone)를 즉시 설계합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #2563EB;">원클릭 클립보드 복사 및 PDF 리포트 지원</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    st.markdown("---")
    
    # 플랫폼 실시간 탐지 통계 요약 (Admin History DB와 동적 연동)
    st.subheader("통합 관제 실시간 위험 지표")
    
    history_data = []
    try:
        res = requests.get(f"{API_URL}/history")
        if res.status_code == 200:
            history_data = res.json()
    except Exception:
        try:
            import sqlite3
            import os
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT id, filename, scan_time, cwe, risk_score, vulnerable FROM scan_history ORDER BY id DESC")
                rows = cursor.fetchall()
                for row in rows:
                    history_data.append({
                        "id": row["id"],
                        "filename": row["filename"],
                        "scan_time": row["scan_time"],
                        "cwe": row["cwe"],
                        "risk_score": row["risk_score"],
                        "vulnerable": bool(row["vulnerable"])
                    })
                conn.close()
        except Exception:
            pass
            
    if history_data:
        import pandas as pd
        df = pd.DataFrame(history_data)
        
        hc1, hc2, hc3 = st.columns(3)
        with hc1:
            st.metric("누적 위협 분석 횟수", f"{len(df)} 회")
        with hc2:
            vuln_count = sum(df["vulnerable"])
            st.metric("누적 보안 결함 검출", f"{vuln_count} 건", delta=f"{vuln_count} 건 발생" if vuln_count > 0 else "0", delta_color="inverse")
        with hc3:
            avg_score = df["risk_score"].mean()
            st.metric("시스템 평균 위험지수", f"{avg_score:.1f} 점")
            
        st.markdown("#### 최근 탐지된 코드 위협 로그 (최근 3건)")
        df_latest = df[["filename", "scan_time", "cwe", "risk_score", "vulnerable"]].head(3).copy()
        df_latest.columns = ["분석 파일명", "진단 일시", "CWE 위협 유형", "리스크 점수", "상태"]
        df_latest["상태"] = df_latest["상태"].map(lambda x: "위협 감지" if x else "안전")
        st.dataframe(df_latest, use_container_width=True, hide_index=True)
    else:
        st.info("데이터베이스에 기록된 정적 분석 이력이 없습니다. Code Vulnerability Patch 탭에서 분석을 진행해 보세요.")

elif menu == "Code Vulnerability Patch":
    st.title("소스코드 취약점 정적 분석 & Safe-Clone 패치")
    st.markdown("Joern CPG 정밀 취약 경로 검출 및 Gemini API 연동 Safe-Clone 보안 교정 패치 엔진")
    st.markdown("---")
    
    col_score, col_ind = st.columns([1, 2])
    
    # RISK SCORE 박스 스타일 개선 (흰색 배경 + 가독성 높은 색상의 숫자 매핑)
    with col_score:
        score_val = st.session_state.risk_score
        
        # 위험 수준에 따른 동적 컬러 매핑 (흰색 배경에 최적화된 고대비 색상)
        if score_val >= 50:
            score_color = "#DC2626"      # 강한 레드
            status_text = "HIGH RISK"
        elif score_val > 0:
            score_color = "#D97706"      # 선명한 오렌지/앰버
            status_text = "WARNING"
        else:
            score_color = "#16A34A"      # 선명한 그린
            status_text = "SECURE"
            
        html_box = f"""
        <div style="
            background-color: #FFFFFF; 
            color: #1E293B;
            padding: 25px; 
            border-radius: 12px; 
            border: 2px solid #000000; 
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05), 0 1px 3px rgba(0, 0, 0, 0.05);
            font-family: ui-sans-serif, system-ui, sans-serif;
        ">
            <span style="font-size: 13px; font-weight: 700; letter-spacing: 1.5px; color: #64748B; text-transform: uppercase;">RISK SCORE</span>
            <h1 style="margin: 8px 0; font-size: 68px; font-weight: 900; color: #000000; line-height: 1.1; font-family: monospace;">{score_val}</h1>
            <span style="background-color: {score_color}15; color: {score_color}; padding: 3px 12px; border-radius: 9999px; font-size: 11px; font-weight: 800; border: 1px solid {score_color}33;">
                {status_text}
            </span>
        </div>
        """
        st.markdown(html_box, unsafe_allow_html=True)
        
    with col_ind:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.session_state.risk_score >= 50:
            st.error("위협 탐지 | SQL 인젝션 / 버퍼 오버플로우 공격 가능 데이터 흐름 포착 | 취약한 코드가 검출되었습니다.")
        elif st.session_state.risk_score > 0 and st.session_state.risk_score < 50:
            st.warning("경고 진단 | 소스코드 무결성 보안 보완 권고")
        else:
            st.success("보안성 무결 | 정적 데이터 흐름(CPG) 분석 결과, 안전함이 보장되었습니다.")

    st.markdown("---")
    
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("진단 대상 소스코드")
        default_code = "$user_input = $_GET['id'];\n$query = \"SELECT * FROM users WHERE id = \" . $user_input;\n$result = mysqli_query($conn, $query);"
        code_data = st.text_area("C / PHP 소스코드 입력 피드", value=default_code, height=220, label_visibility="collapsed")
        btn_scan = st.button("정적 분석 및 Safe-Clone 생성 요청", type="primary", use_container_width=True)

    with c_right:
        st.subheader("보안 대체 Safe-Clone 제안")
        if btn_scan:
            with st.spinner("Joern CPG 그래프 컴파일 및 취약 경로 대조 연산 중..."):
                try:
                    is_c = "strcpy" in code_data or "char buffer" in code_data or "main(" in code_data
                    target_filename = "vulnerable.c" if is_c else "auth.php"
                    
                    res = requests.post(f"{API_URL}/code-analysis", json={"filename": target_filename, "source_code": code_data})
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.analysis_result = data.get("ai_patch_guide")
                        st.session_state.risk_score = data.get("risk_score", 0)
                        st.session_state.filename = data.get("filename", target_filename)
                        st.session_state.matched_cve = data.get("matched_cve", "N/A")
                        st.session_state.vulnerability_details = data.get("vulnerability_details", "")
                        
                        if data.get("vulnerable_clone_found"):
                            st.session_state.risk_status = "HIGH"
                            st.session_state.risk_color = "#EF4444"
                        else:
                            st.session_state.risk_status = "SAFE"
                            st.session_state.risk_color = "#10B981"
                        st.rerun()
                except requests.RequestException:
                    st.error("백엔드 관제 API 서버(Port 8000) 구동 여부를 확인하세요.")
        
        if st.session_state.analysis_result:
            st.markdown(st.session_state.analysis_result)
        else:
            st.info("소스코드 정적 분석 요청 버튼을 클릭하면 최적의 AI 패치 제안 및 대체 가이드가 여기에 출력됩니다.")

    # 하단 유틸리티 버튼 영역 (깔끔하고 세련된 버튼 구성)
    st.markdown("---")
    cb1, cb2, _ = st.columns([1, 1, 3])
    with cb1:
        if st.session_state.analysis_result:
            code_to_copy = extract_code_block(st.session_state.analysis_result)
            render_copy_button(code_to_copy)
        else:
            st.button("패치 코드 복사", disabled=True, use_container_width=True)
            
    with cb2:
        if st.session_state.analysis_result:
            try:
                pdf_data = generate_pdf_report(
                    filename=st.session_state.filename,
                    cwe=st.session_state.matched_cve,
                    risk_score=st.session_state.risk_score,
                    details=st.session_state.vulnerability_details,
                    patch_guide=st.session_state.analysis_result
                )
                st.download_button(
                    label="분석 리포트 PDF 저장",
                    data=pdf_data,
                    file_name=f"K-SecureDev_Report_{st.session_state.filename}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"PDF 리포트 생성 실패: {str(e)}")
        else:
            st.button("분석 리포트 PDF 저장", disabled=True, use_container_width=True)

elif menu == "K-Phishing Scanner":
    st.title("한국어 사칭 스미싱 스캐너")
    st.markdown("인공지능 모델(KoBERT)을 통하여 수신된 메시지의 사회공학적 위협 및 피싱 링크 포함 여부를 스캔합니다.")
    st.markdown("---")
    
    col_score, col_ind = st.columns([1, 2])
    
    # 1. RISK SCORE 박스 (흰색 배경 + 검정 테두리 + 검은 점수 + 상태 배지)
    with col_score:
        score_val = st.session_state.sms_risk_score
        
        # 위험 수준에 따른 동적 컬러 매핑 (흰색 배경에 최적화된 고대비 색상)
        if score_val >= 50:
            score_color = "#DC2626"      # 강한 레드
            status_text = "HIGH RISK"
        elif score_val > 0:
            score_color = "#D97706"      # 선명한 오렌지/앰버
            status_text = "WARNING"
        else:
            score_color = "#16A34A"      # 선명한 그린
            status_text = "SECURE"
            
        html_box = f"""
        <div style="
            background-color: #FFFFFF; 
            color: #1E293B;
            padding: 25px; 
            border-radius: 12px; 
            border: 2px solid #000000; 
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05), 0 1px 3px rgba(0, 0, 0, 0.05);
            font-family: ui-sans-serif, system-ui, sans-serif;
        ">
            <span style="font-size: 13px; font-weight: 700; letter-spacing: 1.5px; color: #64748B; text-transform: uppercase;">RISK SCORE</span>
            <h1 style="margin: 8px 0; font-size: 68px; font-weight: 900; color: #000000; line-height: 1.1; font-family: monospace;">{score_val}</h1>
            <span style="background-color: {score_color}15; color: {score_color}; padding: 3px 12px; border-radius: 9999px; font-size: 11px; font-weight: 800; border: 1px solid {score_color}33;">
                {status_text}
            </span>
        </div>
        """
        st.markdown(html_box, unsafe_allow_html=True)
        
    with col_ind:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.session_state.sms_analysis_result:
            is_phishing = st.session_state.sms_analysis_result.get("analysis_result", {}).get("is_phishing", False)
            threat_type = st.session_state.sms_threat_type
            if is_phishing:
                st.error(f"위협 탐지 | {threat_type} | 입력된 메시지에서 악의적인 스미싱/피싱 패턴이 발견되었습니다.")
            else:
                st.success(f"보안성 무결 | 정상 | 감지된 실시간 스미싱 위협 징후가 존재하지 않습니다.")
        else:
            st.info("문자 본문을 입력한 후 분석을 실행하시면 탐지 결과 및 위협 분류 정보가 여기에 활성화됩니다.")

    st.markdown("---")
    
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("진단 대상 문자 메시지")
        sms_data = st.text_area("SMS 문자 본문", value="[국민은행] 긴급: 비밀번호가 유출되었습니다. http://kb-bank.io/check_acct", height=180, label_visibility="collapsed")
        btn_scan = st.button("의도 분석 및 판독 실행", type="primary", use_container_width=True)

    with c_right:
        st.subheader("AI 사칭 위협 판독 소견")
        if btn_scan:
            with st.spinner("한국어 피싱 문맥 스캔 분석 중..."):
                try:
                    res = requests.post(f"{API_URL}/smishing", json={"text": sms_data})
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.sms_analysis_result = data
                        
                        ans = data.get("analysis_result", {})
                        st.session_state.sms_risk_score = ans.get("risk_score", 0)
                        st.session_state.sms_threat_type = ans.get("threat_type", "알 수 없음")
                        st.session_state.sms_reason = ans.get("reason", "")
                        st.session_state.sms_extracted_urls = data.get("extracted_urls", [])
                        st.session_state.sms_text = sms_data
                        
                        st.rerun()
                except requests.RequestException: 
                    st.error("백엔드 서버와 연동되지 않았습니다.")
                    
        if st.session_state.sms_reason:
            st.markdown(f"#### 판독 유형: **{st.session_state.sms_threat_type}**")
            st.info(st.session_state.sms_reason)
            if st.session_state.sms_extracted_urls:
                st.warning("🔗 **추출된 의심 도메인 (접속 절대 금지):**\n" + "\n".join([f"- {url}" for url in st.session_state.sms_extracted_urls]))
        else:
            st.info("스캔을 실행하면 메시지의 상세 분석 결과가 여기에 출력됩니다.")

    # 하단 유틸리티 버튼 영역 (스미싱 리포트 다운로드 기능 탑재)
    st.markdown("---")
    _, cb_pdf, _ = st.columns([1.5, 2, 1.5])
    with cb_pdf:
        import datetime
        if st.session_state.sms_reason:
            try:
                sms_pdf = generate_smishing_pdf_report(
                    sms_text=st.session_state.sms_text,
                    threat_type=st.session_state.sms_threat_type,
                    risk_score=st.session_state.sms_risk_score,
                    reason=st.session_state.sms_reason,
                    urls=st.session_state.sms_extracted_urls
                )
                st.download_button(
                    label="스미싱 분석 리포트 PDF 저장",
                    data=sms_pdf,
                    file_name=f"K-SecureDev_Smishing_Report_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"PDF 리포트 생성 실패: {str(e)}")
        else:
            st.button("스미싱 분석 리포트 PDF 저장", disabled=True, use_container_width=True)

elif menu == "Admin History":
    st.title("위협 분석 이력 관리")
    st.markdown("K-SecureDev 보안 엔진을 통해 검출되었던 위협 분석 기록을 관리 및 삭제합니다.")
    st.markdown("---")
    
    # API 서버로부터 데이터 이력 조회
    history_data = []
    try:
        res = requests.get(f"{API_URL}/history")
        if res.status_code == 200:
            history_data = res.json()
        else:
            st.error("이력 데이터를 백엔드로부터 검색하지 못했습니다.")
    except requests.RequestException:
        try:
            import sqlite3
            import os
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT id, filename, scan_time, cwe, risk_score, vulnerable, details FROM scan_history ORDER BY id DESC")
                rows = cursor.fetchall()
                for row in rows:
                    history_data.append({
                        "id": row["id"],
                        "filename": row["filename"],
                        "scan_time": row["scan_time"],
                        "cwe": row["cwe"],
                        "risk_score": row["risk_score"],
                        "vulnerable": bool(row["vulnerable"]),
                        "details": row["details"]
                    })
                conn.close()
        except Exception as e:
            st.error(f"로컬 이력 DB 연결 오류: {str(e)}")

    if history_data:
        import pandas as pd
        df = pd.DataFrame(history_data)
        
        # 컬럼명 매핑 및 가독성 개선
        df_display = df[["id", "filename", "scan_time", "cwe", "risk_score", "vulnerable", "details"]].copy()
        df_display.columns = ["이력 ID", "파일명", "탐지 일시", "CWE 위협 유형", "위험도 점수", "취약 여부", "진단 상세 정보"]
        df_display["취약 여부"] = df_display["취약 여부"].map(lambda x: "취약함" if x else "안전")
        
        c_tot, c_vuln, c_avg = st.columns(3)
        with c_tot:
            st.metric("총 분석 횟수", f"{len(df)} 회")
        with c_vuln:
            vuln_count = sum(df["vulnerable"])
            st.metric("취약점 탐지 건수", f"{vuln_count} 건", delta=f"{vuln_count} 위협" if vuln_count > 0 else "0", delta_color="inverse")
        with c_avg:
            avg_score = df["risk_score"].mean()
            st.metric("평균 위험도 점수", f"{avg_score:.1f} 점")
            
        st.markdown("### 전체 검사 이력 로그")
        search_query = st.text_input("검증 파일 또는 위협 유형 키워드 검색", "")
        if search_query:
            df_display = df_display[
                df_display["파일명"].str.contains(search_query, case=False) |
                df_display["CWE 위협 유형"].str.contains(search_query, case=False)
            ]
            
        st.dataframe(df_display, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.subheader("위협 로그 클렌징 및 관리")
        
        c_del, c_clear, _ = st.columns([2, 1.5, 3.5])
        with c_del:
            col_id, col_btn = st.columns([2, 1])
            with col_id:
                del_id = st.number_input("삭제할 이력 ID", min_value=1, step=1, key="del_id_input", label_visibility="collapsed")
            with col_btn:
                if st.button("이력 삭제", type="primary", use_container_width=True):
                    try:
                        res = requests.delete(f"{API_URL}/history/{del_id}")
                        if res.status_code == 200:
                            st.toast(f"이력 ID {del_id} 삭제 완료")
                            st.rerun()
                        else:
                            import sqlite3
                            import os
                            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
                            conn = sqlite3.connect(db_path)
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM scan_history WHERE id = ?", (del_id,))
                            conn.commit()
                            conn.close()
                            st.toast(f"로컬 DB에서 이력 ID {del_id} 삭제 완료")
                            st.rerun()
                    except Exception as e:
                        st.error(f"삭제 오류: {str(e)}")
                        
        with c_clear:
            if st.button("전체 분석 이력 초기화", use_container_width=True):
                try:
                    res = requests.post(f"{API_URL}/history/clear")
                    if res.status_code == 200:
                        st.toast("모든 분석 이력 초기화 완료")
                        st.rerun()
                    else:
                        import sqlite3
                        import os
                        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM scan_history")
                        conn.commit()
                        conn.close()
                        st.toast("로컬 DB 전체 이력 초기화 완료")
                        st.rerun()
                except Exception as e:
                    st.error(f"초기화 오류: {str(e)}")
    else:
        st.info("누적된 위협 탐지 이력이 없습니다.")
