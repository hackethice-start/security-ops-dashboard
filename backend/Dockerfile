# Stage 1: Build wheels (full Python image has gcc/rust/etc)
FROM python:3.12 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Slim runtime image
FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
EXPOSE 4000
# Single worker — critical for APScheduler (multiple workers = multiple schedulers)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4000", "--workers", "1", "--log-level", "info"]
