#!/usr/bin/env python3


import telepot
import telepot.async
import re
import binascii
from capstone import *


class AssemblyBot(telepot.async.Bot):
    UNRECOGNIZED_CONTENT_TYPES = ("voice", "sticker", "photo", "audio",
                                  "document", "video", "contact", "location")
    MESSAGE_REGEX = re.compile(r"^(?:\s*\(\s*(?P<arch>x86|x64)\s*\)\s*)?"
                               r"(?:(?P<bytes>(?:[0-9a-f]{2})+)|"
                               r"(?P<assembly>\S.*))$",
                               re.DOTALL | re.IGNORECASE)

    async def on_chat_message(self, message):
        try:
            await self._process_message(message)
        except:
            await self._send_reply(message, "ERROR: Exception occurred "
                                            "while processing request.")

    async def _send_reply(self, message, text):
        await self.sendMessage(message["chat"]["id"],
                               "<pre>{}</pre>".format(text),
                               parse_mode="HTML",
                               reply_to_message_id=message["message_id"])

    async def _process_message(self, message):
        content_type, chat_type, chat_id = telepot.glance(message)

        if content_type in self.UNRECOGNIZED_CONTENT_TYPES:
            await self._send_reply(message, "ERROR: Message content "
                                            "not understood.")
            return

        match = self.MESSAGE_REGEX.fullmatch(message["text"])
        if not match:
            await self._send_reply(message, "ERROR: Syntax error.")
            return

        if match.group("bytes"):
            result = await self._process_bytes(match.group("arch"),
                                               match.group("bytes"))
        elif match.group("assembly"):
            await self._send_reply(message, "ERROR: Not implemented.")
            return
        else:
            await self._send_reply(message, "ERROR: Not supported.")
            return

        await self._send_reply(message, result)

    async def _process_bytes(self, architecture, raw_bytes):
        architecture = architecture.lower() if architecture else "x86"
        if architecture == "x86":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif architecture == "x64":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            return None

        binary = binascii.unhexlify(raw_bytes)

        return "\n".join("0x%x:\t%s\t%s" % (address, mnemonic, op_str)
                         for address, size, mnemonic, op_str
                         in disassembler.disasm_lite(binary, 0))
