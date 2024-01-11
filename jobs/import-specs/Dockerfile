FROM python:3

WORKDIR /app
RUN pip install requests==2.25.1 pymongo==4.0.1
COPY loadspecs.py entrypoint.sh ./

ENV GIT_REPO="https://github.com/nds-org/ndslabs-specs"
ENV GIT_BRANCH="master"
ENV TARGET_FOLDER="./specs/"

CMD [ "/app/entrypoint.sh" ]
