#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WHUE"""

import os
import time
import ipaddress
import json_log_formatter  # Used in gunicorn_logging.conf
from flask import (
    Flask,
    request,
    render_template,
    make_response,
    abort,
    jsonify,
    send_from_directory,
)
from prometheus_client import multiprocess, generate_latest, Summary
from flask_wtf.csrf import CSRFProtect

application = Flask(__name__, template_folder="templates")

csrf = CSRFProtect()

REQUEST_TIME = Summary("request_processing_seconds", "Time spent processing request")


def checkuseragent():
    if "curl" in request.headers.get("USER_AGENT"):
        return True
    return False


def addressisprivate(ip):
    return ipaddress.ip_address(ip).is_private


@application.route("/index.html", methods=["GET"])
def default_index():
    """Index page"""
    return make_response(render_template("index.html"), 200)


@application.route("/favicon.ico", methods=["GET"])
def favicon():
    """favicon.ico"""
    return send_from_directory(
        os.path.join(application.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@application.route("/healthz", methods=["GET"])
def default_healthz():
    """Index page"""
    return make_response(render_template("index.html"), 200)


@application.route("/metrics", methods=["GET"])
def metrics():
    return generate_latest()


@application.route("/<path:path>", methods=["GET"])
@application.route("/<path:path>")
@REQUEST_TIME.time()
def req_handler(path):
    """GET requests handler"""
    try:
        if request.method == "GET":
            if request.headers.getlist("X-Forwarded-For"):
                ip = request.headers.getlist("X-Forwarded-For")[
                    0
                ]  # search array for non private ip addresses
            elif request.headers.get("X-Real-Ip"):
                ip = request.headers.get("X-Real-Ip")
            else:
                ip = request.remote_addr
            if addressisprivate(ip):
                ip = "private"
            if checkuseragent():
                return ip
        return make_response(render_template("ip.html", ip=ip), 200)
    except:
        print("Error in req_handler()")
        return abort(500)


@application.errorhandler(500)
def resource_error(exception):
    """Internal Error."""
    return jsonify(str(exception)), 500


def child_exit(server, worker):
    multiprocess.mark_process_dead(worker.pid)


if __name__ == "__main__":
    application.run(threaded=True)
    csrf.init_app(application)
