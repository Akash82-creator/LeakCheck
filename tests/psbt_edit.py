"""Edit a serialized PSBT at the key/value-map level, to build malformed inputs
from real (Sparrow-built) PSBTs. Test-only."""

from io import BytesIO

from embit import compact

MAGIC = b"psbt\xff"


def split(raw):
    """[global_map, *input_maps, *output_maps]; each map is a list of [key, value]."""
    assert raw.startswith(MAGIC)
    s, maps, cur = BytesIO(raw[len(MAGIC):]), [], []
    while True:
        try:
            klen = compact.read_from(s)
        except RuntimeError:                       # end of data
            return maps
        if klen == 0:
            maps.append(cur)
            cur = []
            continue
        key = s.read(klen)
        value = s.read(compact.read_from(s))
        cur.append([key, value])


def join(maps):
    out = bytearray(MAGIC)
    for m in maps:
        for key, value in m:
            out += compact.to_bytes(len(key)) + key + compact.to_bytes(len(value)) + value
        out += b"\x00"
    return bytes(out)


def set_field(m, key, value):
    for kv in m:
        if kv[0] == key:
            kv[1] = value
            return
    m.append([key, value])


def drop_field(m, key):
    m[:] = [kv for kv in m if kv[0] != key]
