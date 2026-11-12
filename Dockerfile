FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY stage2_sdk_ai ./stage2_sdk_ai
RUN pip install --no-cache-dir -e ".[audit-s3]"
COPY . .
EXPOSE 10000
CMD ["sh", "-c", "uvicorn stage2_sdk_ai.api:app --host 0.0.0.0 --port ${PORT:-10000}"]
