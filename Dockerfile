FROM python:3.7-alpine

RUN apk add --no-cache git build-base bash cmake
RUN pip install pipenv

WORKDIR /app/AssemblyBot
COPY *.py Pipfile* ./
RUN pipenv install

WORKDIR /app/AssemblyBot
ENTRYPOINT ["pipenv", "run", "python", "./server.py"]
