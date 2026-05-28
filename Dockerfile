FROM python:3.10-slim

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
EXPOSE 8501

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0"]