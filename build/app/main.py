#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WHUE"""

import os
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

application = Flask(__name__, template_folder="templates")

def checkUserAgent():
  if "curl" in request.headers.get("USER_AGENT"):
    return True
  return False

def addressIsPrivate(ip):
   return ipaddress.ip_address(ip).is_private

@application.route("/", methods=["GET"])
def req_handler():
    """GET requests handler"""
    try:
        if request.method == "GET":
          if request.headers.getlist("X-Forwarded-For"):
            ip = request.headers.getlist("X-Forwarded-For")[0] #search array for non private ip addresses
          elif request.headers.get("X-Real-Ip"):
            ip = request.headers.get("X-Real-Ip")
          else:
            ip = request.remote_addr
          if (addressIsPrivate(ip)):
            ip = "private"
          if checkUserAgent():
            return ip
        return make_response(render_template("ip.html",ip=ip), 200)
    except:
        print("Error in req_handler()")
        return abort(500)


@application.errorhandler(500)
def resource_error(exception):
    """Internal Error."""
    return jsonify(str(exception)), 500


@application.route("/index.html")
def default_index():
    """Index page"""
    return make_response(render_template("index.html"), 200)


@application.route("/favicon.ico")
def favicon():
    """favicon.ico"""
    return send_from_directory(
        os.path.join(application.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


if __name__ == "__main__":
    application.run(threaded=True)
