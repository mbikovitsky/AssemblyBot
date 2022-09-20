#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-


import binascii
import html
import re

from aiogram.types import Message
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks


class BotException(Exception):
    """Base class for exceptions raised by the bot"""


class AssemblyBot:
    _COMMAND_REGEX = re.compile(
        r"^\s*/(?P<command>help|about).*$", re.DOTALL | re.IGNORECASE
    )

    _MESSAGE_REGEX = re.compile(
        r"^(?:\s*\(\s*(?P<arch>x86|x64)\s*\)\s*)?"
        r"(?:(?P<bytes>(?:[0-9a-f]{2})+)|"
        r"(?P<assembly>\S.*))$",
        re.DOTALL | re.IGNORECASE,
    )

    _USAGE_TEXT = """I can assemble and disassemble various instructions.

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

    _ABOUT_TEXT = (
        "I'm AssemblyBot. My code is available on "
        '<a href="https://github.com/mbikovitsky/AssemblyBot">GitHub</a>.'
    )

    async def on_chat_message(self, message: Message):
        try:
            if not message.text:
                raise BotException("Message content not understood.")

            if self._is_command(message.text):
                result = self._process_command_text(message.text)
            else:
                result = self._process_query_text(message.text)
            await message.answer(result, parse_mode="HTML")
        except Exception as exception:  # pylint: disable=broad-except
            await message.answer(
                self._format_as_html(f"ERROR: {exception}"), parse_mode="HTML"
            )

    @staticmethod
    def _format_as_html(text):
        return f"<pre>{html.escape(text)}</pre>"

    @classmethod
    def _is_command(cls, text):
        return bool(cls._COMMAND_REGEX.fullmatch(text))

    @classmethod
    def _process_command_text(cls, text):
        match = cls._COMMAND_REGEX.fullmatch(text)
        if not match:
            raise BotException("Unrecognized command.")

        command = match.group("command").lower()
        if command == "help":
            return cls._USAGE_TEXT
        elif command == "about":
            return cls._ABOUT_TEXT
        else:
            raise BotException("Unrecognized command.")

    @classmethod
    def _process_query_text(cls, text):
        match = cls._MESSAGE_REGEX.fullmatch(text)
        if not match:
            raise BotException("Syntax error.")

        if match.group("bytes"):
            result = cls._process_bytes(match.group("arch"), match.group("bytes"))
        elif match.group("assembly"):
            result = cls._process_assembly(match.group("arch"), match.group("assembly"))
        else:
            raise BotException("Not supported.")

        return cls._format_as_html(result)

    @staticmethod
    def _process_bytes(architecture, raw_bytes):
        architecture = architecture.lower() if architecture else "x86"
        if architecture == "x86":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif architecture == "x64":
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise BotException("Unsupported architecture.")

        binary = binascii.unhexlify(raw_bytes)

        return "\n".join(
            f"0x{address:x}:\t{mnemonic}\t{op_str}"
            for address, _size, mnemonic, op_str in disassembler.disasm_lite(binary, 0)
        )

    @staticmethod
    def _process_assembly(architecture, text):
        architecture = architecture.lower() if architecture else "x86"
        if architecture == "x86":
            assembler = Ks(KS_ARCH_X86, KS_MODE_32)
        elif architecture == "x64":
            assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            raise BotException("Unsupported architecture.")

        assembler_output = bytes(assembler.asm(text.encode("UTF-8"))[0])
        return binascii.hexlify(assembler_output).decode("UTF-8")
