# -*- coding: utf-8 -*-
import uuid
from Cookie import SimpleCookie
from os import environ
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from pyramid.events import NewRequest
from pyramid.httpexceptions import HTTPPreconditionFailed
from logging import getLogger
from datetime import datetime
from pytz import timezone
from hashlib import md5

TZ = timezone(environ["TZ"] if "TZ" in environ else "Europe/Kiev")

logger = getLogger(__name__)


def get_time():
    return datetime.now(TZ).isoformat()


def encrypt(sid):
    time = get_time()
    text = "{}{:^{}}".format(sid, time, AES.block_size * 2)
    return hexlify(AES.new(sid).encrypt(text)), time


def decrypt(sid, key):
    try:
        text = AES.new(sid).decrypt(unhexlify(key))
        text.startswith(sid)
    except:
        text = ""
    return text


def server_id_callback(request, response):
    couchdb_server_id = request.registry.couchdb_server_id
    value, time = encrypt(couchdb_server_id)
    response.set_cookie(name="SERVER_ID", value=value)
    logger.info("New cookie: {} ({})".format(value, time), extra={"MESSAGE_ID": "serverid_new"})


def server_id_response(request):
    request.response = HTTPPreconditionFailed()
    request.response.empty_body = True
    request.add_response_callback(server_id_callback)
    return request.response


def server_id_validator(event):
    request = event.request
    couchdb_server_id = request.registry.couchdb_server_id
    cookies = SimpleCookie(request.environ.get("HTTP_COOKIE"))
    cookie_server_id = cookies.get("SERVER_ID", None)
    if cookie_server_id:
        value = cookie_server_id.value
        decrypted = decrypt(couchdb_server_id, value)
        if not decrypted or not decrypted.startswith(couchdb_server_id):
            logger.info("Invalid cookie: {}".format(value, extra={"MESSAGE_ID": "serverid_invalid"}))
            raise server_id_response(request)
    elif request.method in ["POST", "PATCH", "PUT", "DELETE"]:
        raise server_id_response(request)
    if not cookie_server_id:
        request.add_response_callback(server_id_callback)
        return request.response


def includeme(config):
    logger.info("Init server_id NewRequest subscriber")
    server_id = config.registry.server_id
    if server_id == "":
        couchdb_server_id = uuid.uuid4().hex
        config.registry.couchdb_server_id = couchdb_server_id
        logger.warning("No 'server_id' specified. Used generated 'server_id' {}".format(couchdb_server_id))
    else:
        config.registry.couchdb_server_id = md5(server_id).hexdigest()
    config.add_subscriber(server_id_validator, NewRequest)
