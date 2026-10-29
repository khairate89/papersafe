FROM python:3.13.17-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PAPERSAFE_DATA_DIR=/data \
    PAPERSAFE_HOST=0.0.0.0 \
    APP_ENV=development \
    PAPERSAFE_SEED_DEMO=1

WORKDIR /app
RUN useradd --create-home --uid 10001 papersafe \
    && mkdir -p /data \
    && chown papersafe:papersafe /data

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY --chown=papersafe:papersafe app.py ./
COPY --chown=papersafe:papersafe templates ./templates
COPY --chown=papersafe:papersafe static ./static

USER papersafe
EXPOSE 5000
CMD ["python", "app.py"]

