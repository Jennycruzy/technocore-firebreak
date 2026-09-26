FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY firebreak ./firebreak
RUN pip install --no-cache-dir .

USER 65534:65534
ENTRYPOINT ["python", "-m", "firebreak.reference_adapter"]
