#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WHUE"""

import os
import ipaddress
import redis
import json_log_formatter  # Used in gunicorn_logging.conf
from ipwhois.net import Net
from ipwhois.asn import IPASN
from flask import (
    Flask,
    request,
    render_template,
    make_response,
    abort,
    jsonify,
    send_from_directory,
)
from prometheus_client import multiprocess, generate_latest, Summary, CollectorRegistry
from flask_wtf.csrf import CSRFProtect

application = Flask(__name__, template_folder="templates")
csrf = CSRFProtect()

application.config["WHUE_REDIS_HOST"] = str(os.environ.get("WHUE_REDIS_HOST", ""))
application.config["WHUE_REDIS_PORT"] = int(os.environ.get("WHUE_REDIS_PORT", 6379))
application.config["WHUE_ENABLE_REDIS"] = bool(os.environ.get("WHUE_ENABLE_REDIS", False))
application.config["WHUE_REDIS_TIMEOUT"] = int(os.environ.get("WHUE_REDIS_TIMEOUT", 300))
application.config["WHUE_REDIS_CONNECTION"] = None

WHUE_REQUEST_TIME = Summary("whue_request_processing_seconds", "Time spent processing request")
WHUE_WHOIS_REQUEST_TIME = Summary("whue_whois_request_processing_seconds", "Time spent processing request")


def check_user_agent(user_agent):
    """ check client useragent """
    if "curl" in user_agent:
        return True
    return False


def addressisprivate(ip_address):
    """ check that ip is public """
    return ipaddress.ip_address(ip_address).is_private


@application.route("/index.html", methods=["GET"])
def default_index():
    """ index route """
    return make_response(render_template("index.html"), 200)


@application.route("/favicon.ico", methods=["GET"])
def favicon():
    """ favicon.ico """
    return send_from_directory(
        os.path.join(application.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@application.route("/healthz", methods=["GET"])
def default_healthz():
    """healthcheck route"""
    return make_response(render_template("index.html"), 200)


def child_exit(server, worker):
    """ multiprocess function for prometheus to track gunicorn """
    multiprocess.mark_process_dead(worker.pid)


@application.route("/metrics", methods=["GET"])
def metrics():
    """  metrics route """
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    return generate_latest(registry)


def get_set_redis(ip_address, conn):
    """ get set keys in redis """
    if conn.exists(ip_address):
        ip_info = conn.hgetall(ip_address)
    else:
        ip_info = IPASN(Net(ip_address)).lookup()
        conn.hset(ip_address, None, None, ip_info)
    conn.expire(ip_address, application.config["WHUE_REDIS_TIMEOUT"])
    return ip_info


@WHUE_WHOIS_REQUEST_TIME.time()
def get_ip_info(ip_address):
    """ obtain whois information about ip """
    if ip_address:
        obj = (
            get_set_redis(ip_address, application.config["WHUE_REDIS_CONNECTION"])
            if application.config["WHUE_REDIS_CONNECTION"]
            else IPASN(Net(ip_address)).lookup()
        )
    return obj


@application.route("/<path:path>", methods=["GET"])
@application.route("/<path:path>")
@WHUE_REQUEST_TIME.time()
def req_handler(path):
    """ GET requests handler """
    try:
        if request.method == "GET":
            ip_address = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.headers.get("X-Real-Ip")
            ip_info = get_ip_info(ip_address) if ip_address is not None else ""
            if ip_address is None:
                ip_address = "private"
            if check_user_agent(request.headers.get("USER_AGENT")):
                return ip_address
        return make_response(render_template("ip.html", ip=ip_address, ip_info=ip_info), 200)
    except:
        print("Error in req_handler()")
        return abort(500)


def init_redis():
    """ init connection to Redis on start if Redis enabled """
    if application.config["WHUE_ENABLE_REDIS"]:
        application.config["WHUE_REDIS_CONNECTION"] = redis.Redis(
            application.config["WHUE_REDIS_HOST"],
            application.config["WHUE_REDIS_PORT"],
            charset="utf-8",
            decode_responses=True,
        )
        return True
    return False


@application.errorhandler(500) #
def resource_error(exception):
    """ internal error handler """
    return jsonify(str(exception)), 500


if __name__ == "__main__":
    application.run(threaded=True)
    csrf.init_app(application)
    init_redis()
