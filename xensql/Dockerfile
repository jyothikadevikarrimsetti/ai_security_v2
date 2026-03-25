FROM python:3.11-slim

WORKDIR /srv

COPY . /srv/xensql

RUN pip install --no-cache-dir -r /srv/xensql/requirements.txt

ENV PYTHONPATH=/srv

CMD ["uvicorn", "xensql.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
