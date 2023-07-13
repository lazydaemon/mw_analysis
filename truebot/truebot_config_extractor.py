import base64
import malduck
import re
import json
import argparse
from malduck.yara import Yara, YaraString
from smda.Disassembler import Disassembler
from loguru import logger
from typing import Union
from hashlib import sha256
from dataclasses import dataclass

@dataclass
class RC4Key:
    rc4_key_c2: bytes
    rc4_key_commands: bytes

    def __init__(self):
        self.rc4_key_c2 = None
        self.rc4_key_commands = None

@dataclass
class YaraStringData:
    yara_string: YaraString
    start_va: int
    pos: int
    length: int

    def __init__(self, yara_string, start_va=None, length=None, pos=0):
        self.yara_string = yara_string
        self.start_va = start_va
        self.pos = pos
        self.length = length

class Utils:

    @staticmethod
    def extract_ascii_strings(data, min_len=4):

        chars = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNO" \
                b"PQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

        string_list = []
        regexp = b'[%s]{%d,}' % (chars, min_len)
        pattern = re.compile(regexp)
        for s in pattern.finditer(data):
            string_list.append(s.group().decode())
        return string_list

    @staticmethod
    def get_yara_offset(yara_string_data: YaraStringData, data: Union[malduck.procmempe, bytes], matching_result=0):

        offset = None

        rule = Yara(name="rule_name", strings={"one_string": yara_string_data.yara_string}, condition="all of them")
        if isinstance(data, malduck.procmempe):
            match = data.yarav(ruleset=rule, addr=yara_string_data.start_va,
                               length=yara_string_data.length, extended=True)
        else:
            match = rule.match(data=data)
        if match:
            for _, v in match.elements["rule_name"].elements.items():
                if isinstance(data, malduck.procmempe):
                    offset = v[matching_result].offset
                else:
                    offset = v[matching_result]
        if offset:
            return offset + yara_string_data.pos
        else:
            return None

class TrueBotExtractor:

    def __init__(self, filename):
        self.pe = malduck.procmempe.from_file(filename=filename, image=True)

    def get_rc4_key_x64(self, rc4_call_va, lstrlena_calls, rc4):
        """
            0x180027899 FF1551590100                  call qword ptr [rip + 0x15951]
            0x18002789f 4C8BC7                        mov r8, rdi
            0x1800278a2 48 8D 0D 87 60 01 00          lea rcx, [rip + 0x16087]  <--------- We want this line
            0x1800278a9 448BC8                        mov r9d, eax
            0x1800278ac 410FB7D6                      movzx edx, r14w
            0x1800278b0 E83BA7FDFF                    call 0x180001ff0
        """

        offset = Utils.get_yara_offset(YaraStringData(YaraString('48 8D 0D ?? ?? ?? 00', type=YaraString.HEX),
                                                      rc4_call_va - 16, 16, 3), self.pe)
        if offset:
            key = self.pe.uint32v(addr=offset)
            one_byte = self.pe.readv(key + offset - 3, length=1)
            if one_byte == b'\x00':
                i = 2
                while one_byte == b'\x00':
                    one_byte = self.pe.readv(key + offset + i, length=1)
                    i += 1
                rc4_key = self.pe.readv_until(addr=key + offset + i - 1, s=b'\x00')
            else:
                rc4_key = self.pe.readv_until(addr=key + offset, s=b'\x00')
            logger.debug(f'Found RC Key: {rc4_key}')
            rc4.rc4_key_c2 = rc4_key
        else:
            # We are looking for the key which will be used to decrypt the C2 traffic
            # There should be a lstrlenA call right before the rc4_decrypt call
            for call in lstrlena_calls:
                if abs(rc4_call_va - call) < 64:
                    logger.debug(f'Found lstrlenA call at {hex(call)}')
                    # we need to follow the lstrlenA argument now
                    # .text:0000000180028402 F2 0F 10 05 5E 57+     movsd   xmm0, cs:qword_18003DB68
                    # .text:0000000180028402 01 00

                    offset = Utils.get_yara_offset(YaraStringData(YaraString('F2 0F 10 05 ?? ?? ?? 00',
                                                                             type=YaraString.HEX), call - 128, 128, 4),
                                                   self.pe)
                    key = self.pe.uint32v(addr=offset)
                    logger.debug(f'Key: {hex(key + offset + 4 )}')
                    # 8 opcodes
                    one_byte = self.pe.readv(key + offset + 4, length=1)
                    if one_byte == b'\x00':
                        i = 2
                        while one_byte == b'\x00':
                            one_byte = self.pe.readv(key + offset + i, length=1)
                            i += 1
                        rc4_key = self.pe.readv_until(addr=key + offset + i - 1, s=b'\x00')
                    else:
                        rc4_key = self.pe.asciiz(addr=key + offset + 4)
                    logger.debug(f'Found RC Key: {rc4_key}')
                    rc4.rc4_key_commands = rc4_key

    def get_first_rc4_key_x86(self, start_va, rc4):

        offset = Utils.get_yara_offset(YaraStringData(YaraString('C7 45 80 ?? ?? ?? 10', type=YaraString.HEX),
                                                      start_va, 16, 3), self.pe)
        if offset:
            key_offset = self.pe.readv(addr=offset, length=4)
        else:

            offset = Utils.get_yara_offset(YaraStringData(YaraString('68 ?? ?? ?? 10 FF 15', type=YaraString.HEX),
                                                          start_va, 192, 1), self.pe)
            key_offset = self.pe.readv(addr=offset, length=4)

        key_offset = int.from_bytes(key_offset, byteorder="little")
        rc4_key = self.pe.asciiz(addr=key_offset)
        rc4.rc4_key_c2 = rc4_key
        logger.info(f"Found key {rc4_key} at virtual address {hex(key_offset)}")

    def get_second_rc4_key_x86(self, start_va, rc4):

        variants = [YaraStringData(YaraString('E8 ?? ?? ?? ?? A1 ?? ?? ?? 10 F3 0F 7E 05 ?? ?? ?? 10',
                                              type=YaraString.HEX), start_va - 192, 96, 14),
                    YaraStringData(YaraString('E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ??', type=YaraString.HEX),
                                   start_va - 192, 96, 7),
                    YaraStringData(YaraString('BE ?? ?? ?? 10', type=YaraString.HEX),
                                   start_va - 96, 32, 1)
                    ]

        offset = None
        i = 0

        while not offset and i < len(variants):
            try:
                offset = Utils.get_yara_offset(variants[i], self.pe)
                i += 1
            except IndexError:
                logger.exception("Something went wrong.")

        if offset:
            off = self.pe.uint32v(addr=offset)
            rc4_key = self.pe.asciiz(off)
            logger.info(f"Found key {rc4_key} at virtual address {hex(off)}")

            rc4.rc4_key_commands = rc4_key

    def get_mutex_string(self, start_offset: int):

        mutex = None
        if self.pe.pe.is64bit:
            offset = Utils.get_yara_offset(YaraStringData(YaraString('4C 8D 05 ?? ?? ?? 00', type=YaraString.HEX),
                                                          start_offset - 16, 16, 3), self.pe)
            off = self.pe.uint32v(addr=offset)
            offset += off + 4
            mutex = self.pe.utf16z(offset)
        elif self.pe.pe.is32bit:
            # This could break quite easy.
            offset = Utils.get_yara_offset(YaraStringData(YaraString('68 ?? ?? ?? 10', type=YaraString.HEX),
                                                          start_offset - 16, 16, 1), self.pe)
            offset = self.pe.uint32v(addr=offset)
            mutex = self.pe.asciiz(offset)

        return mutex

    @staticmethod
    def prepare_elements(elements: list):
        result = []
        for elem in elements:
            result.extend([elem[i:i + 2] for i in range(0, len(elem), 2)])
        return result

    def custom_decode(self, s: str):
        parts = s.split('%')
        items = self.prepare_elements(parts)
        result = b''
        for item in items:
            if len(item) == 1:
                result += bytes(item, 'ascii')
            else:
                try:
                    if item[0].isupper() or item[1].isupper():
                        result += bytes(item[0], 'ascii')
                        result += bytes(item[1], 'ascii')
                    else:
                        x = int(item, 16).to_bytes(1, 'big')
                        result += x
                except ValueError:
                    result += bytes(item[0], 'ascii')
                    result += bytes(item[1], 'ascii')
        return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("TrueBot Config Extractor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Unpacked sample")
    return parser.parse_args()


def main():
    args = parse_arguments()

    logger.info(f'Extract {args.file}.')
    tbot_extractor = TrueBotExtractor(filename=args.file)
    rc4 = RC4Key()

    rc4_calls = []
    lstrlena_calls = []
    base64_decode_calls = []
    config = {}

    disassembler = Disassembler()
    report = disassembler.disassembleFile(args.file)
    functions = report.getFunctions()

    # TODO
    # CreateMutex is always called inside the relevant export
    # Check if two of our RC4 calls are called from this export, otherwise the RC4 call is wrong

    for fn in functions:

        if fn.offset == 0x1000CE60:
            print("break")

        if len(rc4_calls) == 0:
            # We're searching for 4 RC4_decrypt calls
            if fn.num_inrefs == 4 and 1 <= fn.num_outrefs >= 0 and fn.num_instructions > 50 and fn.num_blocks == 8:
                for item in fn.inrefs:
                    rc4_calls.append(item)

        if len(rc4_calls) == 0:
            # We're searching for 4 RC4_decrypt calls
            if fn.num_inrefs == 3 and 1 <= fn.num_outrefs >= 0 and fn.num_instructions > 50 and fn.num_blocks == 4:
                for item in fn.inrefs:
                    rc4_calls.append(item)

        # If we can't find the 4 RC4_decrypt calls, then our search pattern does not work in this case.
        # Let's try another one.
        if len(rc4_calls) != 4:
            rc4_calls = []
            if fn.num_inrefs == 4 and fn.num_outrefs == 2 and fn.num_instructions < 32 and fn.num_blocks == 1:
                for item in fn.inrefs:
                    rc4_calls.append(item)

        if fn.num_inrefs == 2 and fn.num_outrefs == 8 and fn.num_blocks == 12:
            for item in fn.inrefs:
                base64_decode_calls.append(item)

        for addr, name in fn.apirefs.items():
            if 'kernel32.dll!CreateMutex' in name:
                # There should only one CreateMutex call inside the binary
                mutex = tbot_extractor.get_mutex_string(addr)
                if mutex:
                    config['mutex'] = mutex.decode("utf-8")

                max_ins = 0
                big_block_addr = None
                big_block = None
                for key, value in fn.blocks.items():
                    if len(value) > max_ins:
                        max_ins = len(value)
                        big_block_addr = key
                        big_block = value

            if name == 'kernel32.dll!lstrlenA':
                lstrlena_calls.append(addr)

    if report.bitness == 64:
        for call in rc4_calls:
            tbot_extractor.get_rc4_key_x64(call, lstrlena_calls, rc4)
    elif report.bitness == 32:
        # we can ignore the first two calls since we already have that RC4 call
        tbot_extractor.get_second_rc4_key_x86(start_va=rc4_calls[2], rc4=rc4)

        # big block is the block we are looking for. the magic is in here
        # get the first RC4 key and the base64 strings
        tbot_extractor.get_first_rc4_key_x86(big_block_addr, rc4)

    with open(args.file, "rb") as fp:
        data = fp.read()
        sha256_hash = sha256(data).hexdigest()

    lazy_b64_pattern = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]'
                                  '[AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$')

    c2 = b''
    for s in Utils.extract_ascii_strings(data, min_len=16):
        for a in lazy_b64_pattern.finditer(s):
            tmp = a.group()
            try:
                decoded = base64.b64decode(tmp).decode("utf-8")
                decrypted = malduck.rc4(rc4.rc4_key_c2, tbot_extractor.custom_decode(decoded))
                if decrypted:
                    c2 += decrypted
            except:
                # ignore all non base64 strings
                pass

    config['sha256'] = sha256_hash
    config['c2'] = c2.decode("utf-8")
    config['rc4_key_c2'] = rc4.rc4_key_c2.decode("utf-8")
    config['rc4_key_commands'] = rc4.rc4_key_commands.decode("utf-8")

    print(json.dumps(config, indent=1))


if __name__ == "__main__":
    main()
    print((80 * '-') + '\n')
