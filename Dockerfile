FROM python:3.7-alpine

RUN apk add --no-cache git build-base bash
RUN pip install pipenv

WORKDIR /app/AssemblyBot
COPY *.py Pipfile* ./
RUN pipenv install

ENTRYPOINT ["/app/AssemblyBot/server.py"]
