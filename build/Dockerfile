FROM alphaceti/default-python:0.1.8 as base
ENV PROMETHEUS_MULTIPROC_DIR="/usr/src/app/prometheus" \
    PATH="${PATH}:/home/whue/.local/bin"
ADD app /usr/src/app
RUN addgroup -S whue && \
    adduser -h /home/whue -S whue -G whue && \
    chmod +x /usr/src/app/* && \
    chown -R whue:whue /usr/src/app && \
    apk add --update --no-cache
EXPOSE 5000/tcp
USER whue
WORKDIR /usr/src/app
RUN pip3 install --no-cache-dir -r ./requirements.txt
ENTRYPOINT [ "./entry.sh" ]
