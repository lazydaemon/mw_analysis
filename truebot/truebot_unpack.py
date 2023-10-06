import argparse
import malduck
from loguru import logger
from malduck.yara import Yara, YaraString
from pathlib import Path
from malduck.ints import UInt16


def find_key(pe, dec_call_offset):
    s1 = YaraString('68 ?? ?? ?? ?? [0-8] C7 45 ?? 00 00 00 00 FF 15 [0-10] (89 | 8B) (45 | F0 | F8)',
                    type=YaraString.HEX)
    s2 = YaraString('68 ?? ?? ?? ?? FF 15 [0-10] (89 | 8B) (45 | F0) ?? C7 45', type=YaraString.HEX)
    s3 = YaraString('68 ?? ?? ?? ?? 89 ?? ?? FF 15 ?? ?? ?? ?? (89 | 8B) (45 | F0)', type=YaraString.HEX)

    loop_init = Yara(name="xor_loop", strings={"loop_init1": s1, "loop_init2": s2, "loop_init3": s3},
                     condition="any of them")

    match = pe.yarav(ruleset=loop_init, addr=dec_call_offset, length=256)
    logger.debug(f'Searching for key near virtual address {hex(dec_call_offset)}')
    offset = None
    if match:
        for _, v in match.elements["xor_loop"].elements.items():
            offset = v[0]  # there should only be one match (hopefully)
        if offset:
            # get the offset of the xor key
            key_offset = pe.uint32v(addr=offset + 1)
            xor_key = pe.asciiz(addr=key_offset)
            return xor_key, offset
    return None, None


def find_blob(pe):
    s1 = YaraString('68 ?? ?? (04 | 05 | 06) 00 68 ?? ?? ?? ?? E8',
                    type=YaraString.HEX)
    decrypt_blob_call = Yara(name="decrypt_blob_call", strings={"call": s1}, condition="all of them")
    match = pe.yarav(ruleset=decrypt_blob_call)
    offset = None
    if match:
        for _, v in match.elements["decrypt_blob_call"].elements.items():
            offset = v[0]  # there should only be one match (hopefully)
        if offset:
            logger.debug(f'Found virtual address \'{hex(offset + 10)}\' of call to decryption func.')
            blob_size = pe.uint32v(offset + 1)
            logger.debug(f'Found blob length \'{hex(blob_size)}\' information at '
                         f'{hex(offset)}.')
            # +1 (68) + 4 (4bytes for the blob len) + 1 (68), see the yara rule above
            blob_va = pe.uint32v(offset + 1 + 4 + 1)
            logger.debug(f'Found virtual address \'{hex(blob_va)}\' of encrypted blob start.')

            va_decryption_func = pe.int32v(offset + 1 + 4 + 1 + 4 + 1)
            decryption_func_va = offset + 10 + va_decryption_func + 5
            logger.debug(f'Found decryption function at virtual address \'{hex(decryption_func_va)}\'')
            # edge case, see 7e39dcd15307e7de862b9b42bf556f2836bf7916faab0604a052c82c19e306ca
            jmp = pe.uint8v(addr=decryption_func_va)
            if jmp == 0xE9:
                jmp_offset = pe.uint32v(addr=decryption_func_va + 1)
                decryption_func_va += jmp_offset + 5
            logger.debug(f'Found virtual address \'{hex(decryption_func_va)}\' of decryption function.')

            return blob_size, blob_va, decryption_func_va
    return None, None, None


def find_decryption_param(pe, start_offset):
    s1 = YaraString('24 ?? 32 (C3 | C4 | 45)', type=YaraString.HEX)
    s2 = YaraString('81 E1 ?? 00 00 00 33 C1', type=YaraString.HEX)
    s3 = YaraString('(80 | 81 | 83) (E1 | E2 | E3) ?? (32 | 33)', type=YaraString.HEX)

    and_ins = Yara(name="and_ins", strings={"and1": s1, "and2": s2, "and3": s3}, condition="any of them")

    logger.debug(f'Searching for decryption param near virtual address {hex(start_offset)}')
    match = pe.yarav(ruleset=and_ins, addr=start_offset, length=320)
    if match:
        rule_offset = 2
        _offset = None
        for rulename, o in match.elements["and_ins"].elements.items():
            _offset = o[0]  # there should only be one match (hopefully)
            if rulename == 'and1':
                rule_offset = 1
        param = pe.uint8v(_offset + rule_offset)
        logger.debug(f'Found decryption param "{hex(param)}".')
        return param
    return None


def decrypt(data_blob, key, param):
    result = list(data_blob)
    i = 0
    while i < len(key):
        x = i
        key_xor = key[i] ^ param
        while x <= len(result) - 1:
            result[x] = result[x] ^ key_xor ^ (UInt16(x) & param)
            x += len(key)
        i += 1

    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Truebot Unpacker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Sample path")
    return parser.parse_args()

def dump_file(filename, data):
    with open(filename, 'wb') as fp:
        fp.write(data)
    logger.info(f'Dumped unpacked payload to {filename}.')

def main():
    args = parse_arguments()

    abs_file_path = Path(args.file).resolve()

    logger.info(f"Unpacking {abs_file_path}")
    pe = malduck.procmempe.from_file(filename=abs_file_path, image=True)

    edge_case = True

    blob_len, blob_va, dec_call_offset = find_blob(pe)
    if not [x for x in (blob_len, blob_va, dec_call_offset) if x is None]:
        key, key_offset = find_key(pe, dec_call_offset)
        if key and key_offset:
            logger.info(f'Found key {key}')
            edge_case = False
            param = find_decryption_param(pe, key_offset)
            encrypted_blob = pe.readv(addr=blob_va, length=blob_len)
            decrypted = decrypt(encrypted_blob, key, param)
            dump_file(f'{abs_file_path}.unpacked', bytes(decrypted))
    if edge_case:
        # Edge Case: The decryption function is directly a dll export

        outer_xor_loop1 = YaraString('8A 04 ?? 34 ?? [0-8] 8B ?? 3B FE', type=YaraString.HEX)
        outer_xor_loop2 = YaraString('8B 55 ?? 0F B6 82 ?? ?? ?? ?? [0-8] 88 45 ?? 8B '
                                     '4D ?? 03 4D ?? 89 4D ?? 8B 55 ?? 03 55 ?? 89 55 ??', type=YaraString.HEX)

        inner_xor_loop1 = YaraString('8A D3 DD D8 2A 55 ?? 83 C4 ?? 80 E2 ?? 32 55 ?? 30 13 03 5D ?? 3B DE 72 ??',
                                     type=YaraString.HEX)
        inner_xor_loop2 = YaraString('8A (D9 | D3) 2A DA 80 E3 ?? 32 19 32 D8 88 19 03 4D ?? 3B CE 72 ??',
                                     type=YaraString.HEX)
        inner_xor_loop3 = YaraString('83 C4 ?? 8B 55 ?? 0F B6 02 0F B6 4D ?? 33 C1 8B 55 ?? 2B 55 ?? 0F B6 CA '
                                     '(81 | 83) E1 [0-8] 33 C1 8B 55 ?? 88 02', type=YaraString.HEX)

        xor_loop1 = YaraString('8A C1 2A 45 ?? [0-8 ] 24 ?? 32 (C3 | C4) 30 01 03 CE 81 F9 ?? ?? ?? ??',
                               type=YaraString.HEX)
        xor_loop2 = YaraString('8A C3 B9 ?? ?? ?? ?? 2A C1 83 C4 ?? [0-8] 24 ?? 32 45 ?? 30 03 03 DF 81 FB ?? ?? ?? ??',
                               type=YaraString.HEX)

        decryption_loops = Yara(name="decryption_loops",
                                strings={"outer_xor_loop1": outer_xor_loop1, "outer_xor_loop2": outer_xor_loop2,
                                         "inner_xor_loop1": inner_xor_loop1, "inner_xor_loop2": inner_xor_loop2,
                                         "inner_xor_loop3": inner_xor_loop3,
                                         "xor_loop1": xor_loop1, "xor_loop2": xor_loop2,
                                         }, condition="1 of ($inner_xor_loop*) "
                                                      "and 1 of ($outer_xor_loop*) or 1 of ($xor_loop*)")

        matches = pe.yarav(ruleset=decryption_loops)
        # get offset of first match
        rule_offsets = matches.elements["decryption_loops"]
        offset = None
        for k in rule_offsets.keys():
            offset = rule_offsets.get(k)[0]
            break
        if offset:
            logger.debug(f"Decryption loops found near virtual address {hex(offset)}")
            key, key_offset = find_key(pe, offset - 128)
            if key:
                va_key = pe.uint32v(addr=key_offset + 1)
                logger.info(f'Found key {key} at virtual address {hex(va_key)}')
                # the instruction for reading the decrypted blob must be nearby
                s1 = YaraString('8D (8A | 9E) ?? ?? ?? ?? [0-6] 81 (F9 | FB)', type=YaraString.HEX)
                access_blob = Yara(name="access_blob", strings={"lea_ecx": s1}, condition="any of them")
                match = pe.yarav(ruleset=access_blob, addr=key_offset, length=64)
                access_blob_offset = match.elements["access_blob"].elements["lea_ecx"][0]
                va_blob = pe.uint32v(addr=access_blob_offset + 2)
                logger.info(f'Found blob start at virtual address {hex(va_blob)}')

                for i in range(6):
                    byte = pe.uint8v(addr=key_offset + access_blob_offset + 6 + i)
                    if byte == b'\x81':
                        break

                va_end = pe.uint32v(addr=access_blob_offset + 8 + i)
                logger.info(f'Found blob end at virtual address {hex(va_end)}')
                blob_len = va_end - va_blob
                param = find_decryption_param(pe, key_offset)
                decrypted = decrypt(pe.readv(addr=va_blob, length=blob_len), key, param)
                dump_file(f'{abs_file_path}.unpacked', bytes(decrypted))


if __name__ == "__main__":
    main()
    print("\n")
