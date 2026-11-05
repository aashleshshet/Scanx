FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[web,platform]' && useradd --create-home --uid 10001 scanner
USER scanner
EXPOSE 8080
CMD ["uvicorn", "api_sentry.platform.server:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
