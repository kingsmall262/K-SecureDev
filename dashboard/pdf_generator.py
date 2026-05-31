import io
import os
import re
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

def generate_pdf_report(filename: str, cwe: str, risk_score: int, details: str, patch_guide: str) -> io.BytesIO:
    buffer = io.BytesIO()
    
    # 폰트 등록 (Windows 한글 시스템 기본 폰트인 맑은 고딕 사용)
    font_name = "Helvetica"
    font_bold_name = "Helvetica-Bold"
    
    malgun_path = "C:\\Windows\\Fonts\\malgun.ttf"
    malgun_bold_path = "C:\\Windows\\Fonts\\malgunbd.ttf"
    
    if os.path.exists(malgun_path):
        try:
            pdfmetrics.registerFont(TTFont("MalgunGothic", malgun_path))
            font_name = "MalgunGothic"
            
            if os.path.exists(malgun_bold_path):
                pdfmetrics.registerFont(TTFont("MalgunGothic-Bold", malgun_bold_path))
                font_bold_name = "MalgunGothic-Bold"
            else:
                font_bold_name = "MalgunGothic"
        except Exception:
            pass
            
    # PDF 문서 설정
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45
    )
    
    styles = getSampleStyleSheet()
    
    # 스타일 세팅
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName=font_bold_name,
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#1E3A8A"), # Deep Blue
        alignment=1, # Center
        spaceAfter=25
    )
    
    h1_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName=font_bold_name,
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=18,
        spaceAfter=8
    )
    
    body_style = ParagraphStyle(
        'BodyTextKor',
        parent=styles['Normal'],
        fontName=font_name,
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#374151") # Charcoal
    )
    
    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Normal'],
        fontName=font_name,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1F2937"),
        backColor=colors.HexColor("#F9FAFB"),
        borderColor=colors.HexColor("#E5E7EB"),
        borderWidth=0.5,
        borderPadding=8,
        spaceBefore=6,
        spaceAfter=6
    )
    
    story = []
    
    # 1. 타이틀
    story.append(Paragraph("🛡️ K-SecureDev 보안 취약점 정밀 분석 리포트", title_style))
    story.append(Spacer(1, 5))
    
    # 2. 분석 정보 메타 테이블
    risk_color = "#EF4444" if risk_score >= 50 else ("#F59E0B" if risk_score > 0 else "#10B981")
    risk_text = "위험 (HIGH)" if risk_score >= 50 else ("경고 (WARNING)" if risk_score > 0 else "안전 (SAFE)")
    
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    meta_data = [
        [Paragraph(f"<b>분석 대상 파일명</b>", body_style), Paragraph(filename, body_style)],
        [Paragraph(f"<b>분석 수행 시간</b>", body_style), Paragraph(now_str, body_style)],
        [Paragraph(f"<b>매칭된 CWE 위협</b>", body_style), Paragraph(cwe, body_style)],
        [Paragraph(f"<b>실시간 리스크 점수</b>", body_style), Paragraph(f"<font color='{risk_color}'><b>{risk_text} ({risk_score}점)</b></font>", body_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[140, 380])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F3F4F6")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))
    
    # 3. 상세 취약점 내역
    story.append(Paragraph("🔍 1. 정적 분석 정밀 진단 (Joern CPG)", h1_style))
    # 줄바꿈 처리
    safe_details = details.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
    story.append(Paragraph(safe_details, body_style))
    story.append(Spacer(1, 10))
    
    # 4. AI Safe-Patch 가이드
    story.append(Paragraph("🤖 2. K-SecureDev AI Safe-Clone 패치 가이드", h1_style))
    
    # 마크다운 구문을 파싱하여 텍스트와 코드 블록으로 구분 렌더링
    parts = re.split(r'(```[\w]*\n.*?\n```)', patch_guide, flags=re.DOTALL)
    for part in parts:
        if part.startswith("```"):
            # 코드 블록 추출 및 이스케이프
            code_content = re.sub(r'^```[\w]*\n', '', part)
            code_content = re.sub(r'\n```$', '', code_content)
            code_content_html = code_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>").replace(" ", "&nbsp;")
            story.append(Paragraph(code_content_html, code_style))
        else:
            if part.strip():
                part_html = part.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
                # **볼드** 문구를 <b>볼드</b> 태그로 치환
                part_html = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', part_html)
                # * 리스트 문구를 글머리 기호(bullet)로 보기 좋게 변환
                part_html = re.sub(r'^\*\s+', r'&bull;&nbsp;&nbsp;', part_html, flags=re.MULTILINE)
                story.append(Paragraph(part_html, body_style))
                story.append(Spacer(1, 5))
                
    # 5. 하단 고지사항
    story.append(Spacer(1, 25))
    footer_style = ParagraphStyle(
        'FooterStyle',
        parent=styles['Normal'],
        fontName=font_name,
        fontSize=7.5,
        textColor=colors.HexColor("#9CA3AF"),
        alignment=1
    )
    story.append(Paragraph("본 리포트는 K-SecureDev AI 통합 보안 진단 시스템에 의해 자동 생성된 결과물입니다. 코드 패치를 적용할 때는 반드시 시스템 전체 기능 동치성 테스트를 병행하십시오.", footer_style))
    
    doc.build(story)
    buffer.seek(0)
    return buffer
