FROM python:3

WORKDIR /app
RUN pip install kubernetes==23.6.0
COPY scaledown.py entrypoint.sh ./

ENV NAMESPACE="cheesehub"
ENV TARGET_LABEL_NAME="manager"
ENV TARGET_LABEL_VALUE="workbench"

CMD [ "/app/entrypoint.sh" ]
