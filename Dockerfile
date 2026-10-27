FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/backend:/app
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock
COPY backend /app/backend
COPY agent /app/agent
COPY frontend/dist /app/frontend/dist
COPY examples /app/examples
COPY deploy/entrypoint.py /app/entrypoint.py
USER 10001:10001
ENTRYPOINT ["python", "/app/entrypoint.py"]
