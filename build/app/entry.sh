#!/bin/bash
gunicorn -u `id -u` -g `id -g` --threads=1 --workers=2 --log-config=gunicorn_logging.conf --worker-connections="${WHUE_WORKER_CONN:-500}" --bind="0.0.0.0:5000" main:application
