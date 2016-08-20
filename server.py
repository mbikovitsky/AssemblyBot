#!/usr/bin/env python3


import os
import asyncio
from assembly_bot import AssemblyBot
from contextlib import closing


def main():
    with closing(asyncio.get_event_loop()) as loop:
        # Initialize the bot
        bot = AssemblyBot(os.environ["TELEGRAM_TOKEN"])

        # Set up the event loop
        loop.create_task(bot.message_loop())

        # Run forever
        loop.run_forever()


if __name__ == "__main__":
    main()
