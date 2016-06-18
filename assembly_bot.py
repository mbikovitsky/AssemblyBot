#!/usr/bin/env python3


import telepot
import telepot.async
import re
import binascii
import random
import cgi
from capstone import *
from keystone import *


class BotException(Exception):
    """Base class for exceptions raised by the bot"""
    pass


class AssemblyBot(telepot.async.Bot):
    UNRECOGNIZED_CONTENT_TYPES = ("voice", "sticker", "photo", "audio",
                                  "document", "video", "contact", "location")

    COMMAND_REGEX = re.compile(r"^\s*/(?P<command>help).*$",
                               re.DOTALL | re.IGNORECASE)

    MESSAGE_REGEX = re.compile(r"^(?:\s*\(\s*(?P<arch>x86|x64)\s*\)\s*)?"
                               r"(?:(?P<bytes>(?:[0-9a-f]{2})+)|"
                               r"(?P<assembly>\S.*))$",
                               re.DOTALL | re.IGNORECASE)

    USAGE_TEXT = """I can assemble and disassemble various instructions.

To assemble, send me a message in the following format:
<pre>  (arch) instruction1; instruction2</pre>
You can also separate instructions with newlines.
For example:
<pre>  (x86) xor eax, eax</pre>
Or:
<pre>  (x64)
  begin:
    call get_eip
  get_eip:
    pop eax
    sub eax, get_eip - begin
    ret</pre>

To disassemble, send me a message in the following format:
<pre>  (arch) hex text</pre>
For example:
<pre>  (x64) c3</pre>

Currently, the supported architectures are:
- x86
- x64

If the architecture is omitted, x86 is assumed.
"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._answerer = telepot.async.helper.Answerer(self)

    async def on_chat_message(self, message):
        try:
            content_type, chat_type, chat_id = telepot.glance(message)

            if content_type in self.UNRECOGNIZED_CONTENT_TYPES:
                raise BotException("Message content not understood.")

            message_text = message["text"]

            if self._is_command(message_text):
                result = self._process_command_text(message["text"])
            else:
                result = self._process_query_text(message["text"])
            await self._send_reply(message, result)
        except Exception as e:
            try:
                exception_string = str(e)
            except:
                exception_string = "Unprintable exception."
            finally:
                error_message = "ERROR: " + exception_string
                await self._send_reply(message,
                                       self._format_as_html(error_message))

    async def on_inline_query(self, message):
        query_id, from_id, query_string = telepot.glance(message,
                                                         flavor="inline_query")

        def _compute_answer():
            result = self._process_query_text(query_string)

            return [
                {
                    "type": "article",
                    "id": self._generate_random_id(),
                    "title": "0xDEADBEEF",
                    "input_message_content": {
                        "message_text": self._format_as_html(result),
                        "parse_mode": "HTML"
                    }
                }
            ]

        self._answerer.answer(message, _compute_answer)

    async def _send_reply(self, message, reply):
        await self.sendMessage(message["chat"]["id"],
                               reply,
                               parse_mode="HTML")

    @staticmethod
    def _format_as_html(text):
        return "<pre>{}</pre>".format(cgi.escape(text))

    @staticmethod
    def _generate_random_id():
        # Return a random ID of at most 64 chars in length
        return hex(random.randint(0, 2 ** (32 * 8) - 1))[2:]

    def _is_command(self, text):
        return bool(self.COMMAND_REGEX.fullmatch(text))

    def _process_command_text(self, text):
        match = self.COMMAND_REGEX.fullmatch(text)
        if not match:
            raise BotException("Unrecognized command.")

        command = match.group("command").lower()
        if command == "help":
            return self.USAGE_TEXT
        else:
            raise BotException("Unrecognized command.")

    def _process_query_text(self, text):
        match = self.MESSAGE_REGEX.fullmatch(text)
        if not match:
            raise BotException("Syntax error.")

        if match.group("bytes"):
            result = self._process_bytes(match.group("arch"),
                                         match.group("bytes"))
        elif match.group("assembly"):
            result = self._process_assembly(match.group("arch"),
                                            match.group("assembly"))
        else:
            raise BotException("Not supported.")

        return self._format_as_html(result)

    def _process_bytes(self, architecture, raw_bytes):
        architecture = architecture.lower() if architecture else "x86"
        if architecture == "x86":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif architecture == "x64":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise BotException("Unsupported architecture.")

        binary = binascii.unhexlify(raw_bytes)

        return "\n".join("0x%x:\t%s\t%s" % (address, mnemonic, op_str)
                         for address, size, mnemonic, op_str
                         in disassembler.disasm_lite(binary, 0))

    def _process_assembly(self, architecture, text):
        architecture = architecture.lower() if architecture else "x86"
        if architecture == "x86":
            assembler = Ks(KS_ARCH_X86, KS_MODE_32)
        elif architecture == "x64":
            assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            raise BotException("Unsupported architecture.")

        assembler_output = bytes(assembler.asm(text.encode("UTF-8"))[0])
        return binascii.hexlify(assembler_output).decode("UTF-8")
