FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY backend /app/backend

ENV PYTHONPATH=/app
EXPOSE 8010

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8010"]
