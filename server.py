#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-


import asyncio
import os
from contextlib import closing

from aiohttp import web

from assembly_bot import AssemblyBot


g_update_queue = None


async def _webhook(request):
    data = await request.text()
    await g_update_queue.put(data)
    return web.Response(body="OK".encode("UTF-8"))


def _main():
    global g_update_queue  # pylint: disable=global-statement

    with closing(asyncio.get_event_loop()) as loop:
        token = os.environ["TELEGRAM_TOKEN"]

        # Initialize the bot
        bot = AssemblyBot(token)

        # Initialize webhooks if we have a URL
        base_url = os.environ.get("BASE_URL", "").rstrip("/")
        if base_url:
            # Create a queue
            g_update_queue = asyncio.Queue()

            webhook_path = "/" + token

            # Create a webserver
            app = web.Application()
            app.router.add_route("GET", webhook_path, _webhook)
            app.router.add_route("POST", webhook_path, _webhook)

            # Register the server with the event loop
            port = int(os.environ["PORT"]) if "PORT" in os.environ else 80
            loop.run_until_complete(
                loop.create_server(app.make_handler(), "0.0.0.0", port)
            )

            # Set the webhook URL with Telegram
            loop.run_until_complete(bot.setWebhook(base_url + webhook_path))
        else:
            # Clear the webhook URL
            loop.run_until_complete(bot.setWebhook())

        # Create the bot task
        loop.create_task(bot.message_loop(source=g_update_queue))

        # Run forever
        loop.run_forever()


if __name__ == "__main__":
    _main()
