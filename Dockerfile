FROM python:3.11-slim
WORKDIR /app
ENV APP_DATA_DIR=/var/data
RUN mkdir -p /var/data && chown 10001:10001 /var/data
COPY pyproject.toml README.md ./
COPY stage2_sdk_ai ./stage2_sdk_ai
RUN pip install --no-cache-dir -e ".[audit-s3]"
COPY . .
EXPOSE 10000
CMD ["python", "scripts/render_entrypoint.py"]
