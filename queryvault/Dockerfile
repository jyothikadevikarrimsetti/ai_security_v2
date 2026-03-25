FROM python:3.11-slim

WORKDIR /srv

COPY . /srv/queryvault

RUN pip install --no-cache-dir -r /srv/queryvault/requirements.txt

ENV PYTHONPATH=/srv

CMD ["uvicorn", "queryvault.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
