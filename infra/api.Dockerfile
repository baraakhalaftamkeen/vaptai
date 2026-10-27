FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

# System deps kept minimal; add scanner tools only in worker images, not the API.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/backend.txt requirements/backend.txt
RUN pip install --no-cache-dir -r requirements/backend.txt

# Monorepo packages + the API service.
COPY packages/ packages/
COPY services/api/ services/api/
COPY migrations/ migrations/

ENV PYTHONPATH=/srv/packages/domain:/srv/packages/persistence:/srv/packages/llm_gateway:/srv/packages/policy:/srv/packages/tools:/srv/services/api

EXPOSE 8000
CMD ["uvicorn", "vapt_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
