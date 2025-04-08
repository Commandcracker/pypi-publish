FROM docker.io/python:3.13.2-alpine

COPY requirements.txt main.py /

RUN pip install --no-cache-dir --requirement requirements.txt

CMD ["python", "/main.py"]
