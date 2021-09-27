FROM alphaceti/default-python:0.1.3 as base
COPY app/requirements.txt /usr/src/app/
RUN pip3 install -r /usr/src/app/requirements.txt && \
    find / -type d -name __pycache__ -exec rm -r {} +   && \
    rm -rf /usr/lib/python*/ensurepip                   && \
    rm -rf /usr/lib/python*/turtledemo                  && \
    rm -rf /usr/lib/python*/idlelib                     && \
    rm -f /usr/lib/python*/turtle.py                    && \
    rm -f /usr/lib/python*/webbrowser.py                && \
    rm -f /usr/lib/python*/doctest.py                   && \
    rm -f /usr/lib/python*/pydoc.py                     && \
    rm -rf /root/.cache /var/cache
FROM base
ENV PROMETHEUS_MULTIPROC_DIR="/usr/src/app/prometheus"
ADD app /usr/src/app
RUN addgroup -S whue && adduser -S whue -G whue && \
    chmod +x /usr/src/app/* && chown -R whue:whue /usr/src/app
EXPOSE 5000/tcp
USER whue
WORKDIR /usr/src/app
ENTRYPOINT [ "./entry.sh" ]
