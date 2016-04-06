#!/usr/bin/env python3


import telepot


class AssemblyBot(telepot.Bot):
    def on_chat_message(self, msg):
        content_type, chat_type, chat_id = telepot.glance(msg)
        print('Normal Message:', content_type, chat_type, chat_id)
