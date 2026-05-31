import streamlit as st
import requests
import re
from dashboard.pdf_generator import generate_pdf_report

API_URL = "http://localhost:8000/api/v1"

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
        background-color: #4F46E5;
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
        📋 패치 코드 복사하기
    </button>
    <div id="status" style="
        color: #10B981; 
        font-size: 0.75rem; 
        margin-top: 4px; 
        text-align: center; 
        font-family: sans-serif; 
        display: none;
        font-weight: bold;
    ">✅ 복사 완료!</div>
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

# 사이드바 레이아웃
st.sidebar.title("⚡ K-SecureDev")
st.sidebar.markdown("---")
menu = st.sidebar.radio("통합 관제 메뉴 레이어", ["Dashboard Home", "K-Phishing Scanner", "Code Vulnerability Patch", "Admin History"])

if menu == "Dashboard Home":
    st.title("🛡️ K-SecureDev 통합 보안 비서 관제 센터")
    st.markdown("한국형 사회공학적 위협 탐지 및 정적 분석(CPG)과 AI Safe-Clone 패치 관리를 위한 통합 플랫폼입니다.")
    st.markdown("---")
    
    # 웰컴 배너 및 핵심 설명
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #1E3A8A 0%, #3B82F6 100%); padding: 30px; border-radius: 12px; color: white; margin-bottom: 25px;">
            <h2 style="margin: 0; font-size: 28px; font-weight: 700;">Welcome to K-SecureDev Portal</h2>
            <p style="margin: 10px 0 0 0; font-size: 15px; opacity: 0.9; line-height: 1.6;">
                K-SecureDev는 국내 특유의 문맥적 사칭 스미싱 메시지를 포착하는 <b>한국어 특화 탐지 엔진(KoBERT)</b>과, 소스코드의 비검증 데이터 흐름을 정적 기법으로 정밀 진단하는 <b>CPG 정적 분석기(Joern)</b>, 그리고 탐지된 취약점에 대해 시스템의 무결성을 깨뜨리지 않는 가장 안전한 패치 코드를 제안하는 <b>AI Safe-Clone 모델(Gemini)</b>이 융합된 차세대 통합 보안 관제 플랫폼입니다.
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
            <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 200px;">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 16px;">💬 K-Phishing Scanner</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5;">한국어 문장 구조 및 조사의 차이까지 정밀하게 읽어내어 일반 안내 메시지와 사회공학적 사칭 문자를 완벽히 구분 판독합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #3B82F6; cursor: pointer;">👈 사이드바 [K-Phishing Scanner] 선택</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            """
            <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 200px;">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 16px;">🔍 Joern CPG Engine</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5;">소스코드 내부를 정형 그래프 형태(CPG)로 변환해 외부 유입 데이터가 위험 싱크(strcpy 등)로 흘러 들어가는 보안 위협 흐름을 추적합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #3B82F6; cursor: pointer;">👈 사이드바 [Code Vulnerability Patch] 선택</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            """
            <div style="background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 22px; border-radius: 8px; min-height: 200px;">
                <h4 style="margin-top: 0; color: #1E3A8A; font-size: 16px;">🤖 Gemini AI Safe-Patch</h4>
                <p style="font-size: 13px; color: #475569; line-height: 1.5;">검출된 정적 분석 결과를 바탕으로, 프로젝트의 구문 및 데이터 흐름 일치도(CodeBLEU 0.85↑)를 만족하는 보안 교정 패치 코드를 실시간 생성합니다.</p>
                <span style="font-size: 12px; font-weight: bold; color: #3B82F6;">📋 클립보드 복사 및 PDF 파일 추출 지원</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    st.markdown("---")
    
    # 📊 플랫폼 실시간 탐지 통계 요약 (Admin History DB와 동적 연동)
    st.subheader("📊 플랫폼 실시간 위협 관제 통계")
    
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
            st.metric("누적 보안 취약 소스코드 검출", f"{vuln_count} 건", delta=f"{vuln_count} 건 발생" if vuln_count > 0 else "0", delta_color="inverse")
        with hc3:
            avg_score = df["risk_score"].mean()
            st.metric("시스템 평균 위험지수", f"{avg_score:.1f} 점")
            
        st.markdown("#### 🚨 실시간 최신 탐지 결함 로그 (최근 3건)")
        df_latest = df[["filename", "scan_time", "cwe", "risk_score", "vulnerable"]].head(3).copy()
        df_latest.columns = ["분석 파일명", "진단 일시", "탐지된 CWE 위협 유형", "리스크 점수", "취약 상태"]
        df_latest["취약 상태"] = df_latest["취약 상태"].map(lambda x: "🔴 취약점 발견" if x else "🟢 안전함")
        st.dataframe(df_latest, use_container_width=True, hide_index=True)
    else:
        st.info("💡 현재 데이터베이스에 기록된 정적 분석 이력이 존재하지 않습니다. [Code Vulnerability Patch] 탭에서 첫 코드 스캔을 구동하시면 플랫폼 관제 통계 보드가 실시간으로 활성화됩니다!")

elif menu == "Code Vulnerability Patch":
    st.title("🛡️ 소스코드 취약점 정적 분석 & Safe-Clone 패치")
    st.markdown("C / PHP 소스코드를 업로드하여 Joern CPG 정밀 취약 흐름을 검출하고 AI가 안전하게 보완한 패치 가이드를 제공합니다.")
    st.markdown("---")
    
    col_score, col_ind = st.columns([1, 2])
    with col_score:
        html_box = "<div style='background-color: #F3F4F6; padding: 20px; border-radius: 10px; border-left: 5px solid " + st.session_state.risk_color + "; text-align: center;'>"
        html_box += "<h3 style='margin:0; color:" + st.session_state.risk_color + ";'>RISK SCORE</h3>"
        html_box += "<h1 style='margin:0; font-size:64px;'>" + str(st.session_state.risk_score) + "</h1>"
        html_box += "<p style='margin:0; font-weight:bold; color:" + st.session_state.risk_color + ";'>" + st.session_state.risk_status + "</p>"
        html_box += "</div>"
        st.markdown(html_box, unsafe_allow_html=True)
        
    with col_ind:
        st.markdown("<br><br>", unsafe_allow_html=True)
        if st.session_state.risk_score >= 50:
            st.error("🔴 위협 탐지 | 🔴 SQL 인젝션 / 버퍼 오버플로우 위협 패스 발견 | 🔴 취약한 코드 발견")
        elif st.session_state.risk_score > 0 and st.session_state.risk_score < 50:
            st.warning("🟡 경고 진단 | 기저 구조적 무결성 점검 필요")
        else:
            st.success("🟢 보안성 무결 | 현재 감지된 실시간 위협 데이터 흐름이 존재하지 않습니다.")

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
                    # 입력 파일 형식 자동 감지
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
                    st.error("백엔드 서버(Port 8000) 구동 상태를 확인하세요.")
        
        if st.session_state.analysis_result:
            st.markdown(st.session_state.analysis_result)
        else:
            st.caption("분석 실행 버튼을 누르면 패치 코드가 여기에 빌드됩니다.")

    # 하단 유틸리티 버튼 영역
    st.markdown("---")
    cb1, cb2, _ = st.columns([1, 1, 3])
    with cb1:
        if st.session_state.analysis_result:
            code_to_copy = extract_code_block(st.session_state.analysis_result)
            render_copy_button(code_to_copy)
        else:
            st.button("📋 패치 코드 복사하기", disabled=True)
            
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
                    label="📥 분석 리포트 PDF 저장",
                    data=pdf_data,
                    file_name=f"K-SecureDev_Report_{st.session_state.filename}.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"PDF 리포트 생성 에러: {str(e)}")
        else:
            st.button("📥 분석 리포트 PDF 저장", disabled=True)

elif menu == "K-Phishing Scanner":
    st.subheader("💬 한국어 특화 사칭 스미싱 스캐너")
    sms_data = st.text_area("SMS 문자 본문", value="[국민은행] 긴급: 비밀번호가 유출되었습니다. http://kb-bank.io/check_acct")
    if st.button("사회공학적 의도 판독"):
        try:
            res = requests.post(f"{API_URL}/smishing", json={"text": sms_data})
            if res.status_code == 200:
                st.json(res.json())
        except requests.RequestException: 
            st.error("백엔드 서버 연동 실패")

elif menu == "Admin History":
    st.title("🗄️ K-SecureDev 위협 분석 이력 관리")
    st.markdown("시스템을 통해 수행된 소스코드 취약점 및 악성 흐름 검사 이력을 모니터링하고 관리합니다.")
    st.markdown("---")
    
    # API 서버로부터 데이터 이력 조회
    history_data = []
    try:
        res = requests.get(f"{API_URL}/history")
        if res.status_code == 200:
            history_data = res.json()
        else:
            st.error("백엔드 서버로부터 이력 데이터를 가져올 수 없습니다.")
    except requests.RequestException:
        # 백엔드 비활성화 시 로컬 SQLite DB 직접 연동 백업 모드
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
            st.error(f"로컬 이력 DB 직접 로드 오류: {str(e)}")

    if history_data:
        import pandas as pd
        df = pd.DataFrame(history_data)
        
        # 보기 쉽게 컬럼명 맵핑 및 가독성 개선
        df_display = df[["id", "filename", "scan_time", "cwe", "risk_score", "vulnerable", "details"]].copy()
        df_display.columns = ["이력 ID", "파일명", "탐지 일시", "탐지된 CWE", "위험도 점수", "취약 여부", "상세 진단 정보"]
        df_display["취약 여부"] = df_display["취약 여부"].map(lambda x: "🔴 취약함" if x else "🟢 안전함")
        
        # 상단 실시간 요약 통계 정보 제공
        c_tot, c_vuln, c_avg = st.columns(3)
        with c_tot:
            st.metric("총 분석 횟수", f"{len(df)} 회")
        with c_vuln:
            vuln_count = sum(df["vulnerable"])
            st.metric("취약점 탐지 건수", f"{vuln_count} 건", delta=f"{vuln_count} 위협" if vuln_count > 0 else "0", delta_color="inverse")
        with c_avg:
            avg_score = df["risk_score"].mean()
            st.metric("평균 위험도 점수", f"{avg_score:.1f} 점")
            
        st.markdown("### 📋 전체 검사 로그 리스트")
        # 데이터 검색 필터 구현
        search_query = st.text_input("🔍 파일명 또는 CWE 위협 키워드 검색", "")
        if search_query:
            df_display = df_display[
                df_display["파일명"].str.contains(search_query, case=False) |
                df_display["탐지된 CWE"].str.contains(search_query, case=False)
            ]
            
        st.dataframe(df_display, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.subheader("⚙️ 관리 데이터 클렌징")
        
        c_del, c_clear, _ = st.columns([2, 1.5, 3.5])
        with c_del:
            col_id, col_btn = st.columns([2, 1])
            with col_id:
                del_id = st.number_input("삭제할 이력 번호(ID) 입력", min_value=1, step=1, key="del_id_input")
            with col_btn:
                st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
                if st.button("🗑️ 선택 삭제", type="primary", use_container_width=True):
                    try:
                        res = requests.delete(f"{API_URL}/history/{del_id}")
                        if res.status_code == 200:
                            st.toast(f"ID {del_id} 이력이 삭제되었습니다.")
                            st.rerun()
                        else:
                            # DB 직접 삭제 시도 (API 백업 모드)
                            import sqlite3
                            import os
                            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
                            conn = sqlite3.connect(db_path)
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM scan_history WHERE id = ?", (del_id,))
                            conn.commit()
                            conn.close()
                            st.toast(f"ID {del_id} 이력이 로컬 DB에서 직접 삭제되었습니다.")
                            st.rerun()
                    except Exception as e:
                        st.error(f"이력 삭제에 실패했습니다: {str(e)}")
                        
        with c_clear:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            if st.button("🚨 전체 분석 이력 초기화", use_container_width=True):
                try:
                    res = requests.post(f"{API_URL}/history/clear")
                    if res.status_code == 200:
                        st.toast("모든 분석 이력이 초기화되었습니다.")
                        st.rerun()
                    else:
                        # DB 직접 초기화
                        import sqlite3
                        import os
                        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "history.db")
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM scan_history")
                        conn.commit()
                        conn.close()
                        st.toast("로컬 DB의 전체 분석 이력이 직접 초기화되었습니다.")
                        st.rerun()
                except Exception as e:
                    st.error(f"이력 전체 초기화에 실패했습니다: {str(e)}")
    else:
        st.info("💡 누적된 위협 탐지 이력이 아직 존재하지 않습니다. 첫 정적 분석을 수행해 보세요!")
