FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/backend.txt requirements/backend.txt
RUN pip install --no-cache-dir -r requirements/backend.txt

COPY packages/ packages/
COPY services/orchestrator/ services/orchestrator/

ENV PYTHONPATH=/srv/packages/domain:/srv/packages/persistence:/srv/packages/llm_gateway:/srv/packages/policy:/srv/packages/tools:/srv/services/orchestrator

# One leader scheduler + bounded concurrency. Tool binaries get added to this image
# (or dedicated runner images) as adapters land in Weeks 3-4.
CMD ["celery", "-A", "vapt_orch.celery_app.celery_app", "worker", "--loglevel=info", "--concurrency=2", "-Q", "runs"]
