FROM python:3.9
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["python", "server.py"]

# Read version metadata from build-args
ARG VERSION=unknown
ARG BRANCH=unknown
ARG GITSHA1=unknown
ARG BUILDNUMBER=unknown
ENV VERSION=${VERSION}
ENV BRANCH=${BRANCH}
ENV GITSHA1=${GITSHA1}
ENV BUILDNUMBER=${BUILDNUMBER}

