FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY secureflow ./secureflow
RUN pip install .

RUN useradd --create-home --uid 1000 secureflow && mkdir -p /deployments && chown secureflow /deployments
USER secureflow

EXPOSE 8000
CMD ["uvicorn", "secureflow.api:app", "--host", "0.0.0.0", "--port", "8000"]
