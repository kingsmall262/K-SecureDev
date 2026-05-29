FROM python:3.10-slim

# 1. Joern 구동에 필수적인 Java 및 인프라 유틸리티 패키지 무조건 설치
RUN apt-get update && apt-get install -y \
    default-jdk \
    wget \
    unzip \
    curl \
    git \
    && apt-get clean

# 2. 공식 Joern 최신 안정 버전 다운로드 및 자동 설치 프로세스 가동
RUN wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh \
    && chmod +x joern-install.sh \
    && ./joern-install.sh --version=v2.0.4

# 3. 파이썬 작업 디렉토리 설정 및 의존성 라이브러리 이식
WORKDIR /workspace
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
EXPOSE 8501

# 프론트엔드 및 백엔드 동시 가동
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0"]