#!/usr/bin/env python3


import os
import asyncio
from aiohttp import web
from assembly_bot import AssemblyBot
from contextlib import closing


g_update_queue = None


async def webhook(request):
    data = await request.text()
    await g_update_queue.put(data)
    return web.Response(body="OK".encode("UTF-8"))


def main():
    global g_update_queue

    with closing(asyncio.get_event_loop()) as loop:
        token = os.environ["TELEGRAM_TOKEN"]

        # Initialize the bot
        bot = AssemblyBot(token)

        # Initialize webhooks if we have a URL
        try:
            base_url = os.environ["BASE_URL"].rstrip("/")
        except:
            base_url = None
        if base_url:
            # Create a queue
            g_update_queue = asyncio.Queue()

            webhook_path = "/" + token

            # Create a webserver
            app = web.Application()
            app.router.add_route("GET", webhook_path, webhook)
            app.router.add_route("POST", webhook_path, webhook)

            # Register the server with the event loop
            port = int(os.environ["PORT"]) if "PORT" in os.environ else 80
            loop.run_until_complete(loop.create_server(app.make_handler(),
                                                       "0.0.0.0",
                                                       port))

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
    main()
