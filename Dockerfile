FROM docker.io/python:3.12.3-bookworm

COPY requirements.txt /.
COPY main.py /.

ENV PIP_ROOT_USER_ACTION=ignore

RUN set -eux; \
    pip install --upgrade pip; \
    pip install --no-cache-dir --requirement requirements.txt

CMD ["python", "/main.py"]
