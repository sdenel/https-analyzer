FROM python:3.8-alpine
RUN apk add bind-tools && \
    pip install -U Jinja2 requests && \
    apk add gcc musl-dev libffi-dev openssl-dev && \
    pip install -U pyopenssl && \
    apk del gcc musl-dev libffi-dev openssl-dev

COPY / /opt/
WORKDIR /opt/

# Running unit tests
RUN python3 -m doctest -v https-analyzer.py

ENTRYPOINT ["/opt/https-analyzer.py"]
