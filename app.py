#!/usr/bin/env python3


import os
from flask import Flask, request, url_for
from queue import Queue
from assembly_bot import AssemblyBot


TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]


# Configure the application
app = Flask(__name__)
app.config["SERVER_NAME"] = os.environ["SERVER_NAME"]
app.config["PREFERRED_URL_SCHEME"] = "https"


@app.route("/" + TELEGRAM_TOKEN, methods=["GET", "POST"])
def pass_update():
    update_queue.put(request.data)
    return 'OK'


# Configure the bot
update_queue = Queue()
bot = AssemblyBot(TELEGRAM_TOKEN)
bot.notifyOnMessage(source=update_queue)
with app.app_context():
    bot.setWebhook(url_for("pass_update"))
