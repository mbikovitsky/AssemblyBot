#!/usr/bin/env python3


import os
import asyncio
from urllib.parse import urlunparse
from aiohttp import web
from assembly_bot import AssemblyBot


TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
SERVER_NAME = os.environ["SERVER_NAME"]
PORT = int(os.environ["PORT"])
HOST = "0.0.0.0"
WEBHOOK_ROUTE = "/" + TELEGRAM_TOKEN


class WebhookView(web.View):
    """Handles requests to the webhook URL"""

    async def get(self):
        return await self.post()

    async def post(self):
        data = await self.request.text()
        await self.request.app["update_queue"].put(data)
        return web.Response(body="OK".encode("UTF-8"))


async def init(loop):
    # Initialize the server
    app = web.Application(loop=loop)
    app["update_queue"] = asyncio.Queue(loop=loop)
    app.router.add_route("*", WEBHOOK_ROUTE, WebhookView)
    server = await loop.create_server(app.make_handler(), HOST, PORT)

    # Initialize the bot
    bot = AssemblyBot(TELEGRAM_TOKEN, loop=loop)
    loop.create_task(bot.messageLoop(source=app["update_queue"]))
    await bot.setWebhook(urlunparse(("https",
                                     SERVER_NAME,
                                     WEBHOOK_ROUTE,
                                     "", "", "")))

    return server


loop = asyncio.get_event_loop()
server = loop.run_until_complete(init(loop))
loop.run_forever()
