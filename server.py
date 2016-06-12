#!/usr/bin/env python3


import os
import asyncio
from assembly_bot import AssemblyBot


TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]


# Initialize the bot
bot = AssemblyBot(TELEGRAM_TOKEN)

# Set up the event loop
loop = asyncio.get_event_loop()
loop.create_task(bot.message_loop())

# Run forever
loop.run_forever()
