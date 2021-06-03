import struct


class Utils:
    @staticmethod
    def url_from_bytes(data: bytes, offset: int, rec=False):
        output = ""
        while data[offset] != 0 and data[offset] < 0x80:
            for i in range(1, data[offset] + 1):
                output += chr(data[offset + i])
            output += "."
            offset += data[offset] + 1
        if data[offset] >= 0x80:
            end_offset = Utils.short_from_bytes(data, offset)[0] & 0x1FFF
            output += Utils.url_from_bytes(data, end_offset, True)[0]
            offset += 1
        if not rec:
            output = output[:-1]
        return (output, offset + 1)

    @staticmethod
    def url_to_bytes(url: str):
        data = b""
        for part in url.split("."):
            data += struct.pack("B", len(part))
            data += part.encode(encoding="utf-8")
        return data + b"\0"

    @staticmethod
    def short_from_bytes(data: bytes, offset: int):
        return (struct.unpack_from("!H", data, offset)[0], offset + 2)

    @staticmethod
    def int_from_bytes(data: bytes, offset: int):
        return (struct.unpack_from("!I", data, offset)[0], offset + 4)
