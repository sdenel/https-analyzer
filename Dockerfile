FROM python:3.8-alpine
RUN apk add bind-tools && pip install -U Jinja2

COPY / /opt/
WORKDIR /opt/

# Running unit tests
RUN python3 -m doctest -v https-analyzer.py

ENTRYPOINT ["/opt/https-analyzer.py"]