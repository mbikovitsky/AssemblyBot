#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-


import os

from aiogram import Bot, Dispatcher, executor, types
from aiogram.utils.executor import start_webhook

from assembly_bot import AssemblyBot


def _main():
    token = os.environ["TELEGRAM_TOKEN"]

    bot = Bot(token)
    dispatcher = Dispatcher(bot)

    actual_bot = AssemblyBot()

    @dispatcher.message_handler()
    async def handle_message(message: types.Message):
        await actual_bot.on_chat_message(message)

    # Initialize webhooks if we have a URL
    base_url = os.environ.get("BASE_URL", "").rstrip("/")
    if base_url:
        webhook_path = "/" + token

        async def on_startup(dispatcher):
            await bot.set_webhook(base_url + webhook_path)

        async def on_shutdown(dispatcher):
            await bot.delete_webhook()

        start_webhook(
            dispatcher=dispatcher,
            webhook_path=webhook_path,
            on_startup=on_startup,
            on_shutdown=on_shutdown,
            skip_updates=True,
            host="0.0.0.0",
            port=int(os.environ["PORT"]) if "PORT" in os.environ else 80,
        )
    else:
        # No URL, going to poll

        async def on_startup(dispatcher):
            await bot.delete_webhook()

        executor.start_polling(dispatcher, on_startup=on_startup, skip_updates=True)


if __name__ == "__main__":
    _main()
