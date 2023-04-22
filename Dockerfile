FROM python:3
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

ARG VERSION=unknown
ARG BRANCH=unknown
ARG GITSHA1=unknown
ARG BUILDNUMBER=unknown

COPY . .
CMD ["python", "server.py"]

