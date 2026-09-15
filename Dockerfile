FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
RUN addgroup --system --gid 10001 agentshield \
    && adduser --system --uid 10001 --ingroup agentshield agentshield
COPY --chown=agentshield:agentshield . .
RUN mkdir -p /app/output && chown agentshield:agentshield /app/output

USER 10001:10001

EXPOSE 8080 8501
CMD ["python", "src/api.py"]
