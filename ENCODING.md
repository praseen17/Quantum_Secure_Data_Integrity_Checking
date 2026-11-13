# Q-SAFE Canonical Encoding

This document defines the bytes used by every Q-SAFE structure that is hashed or signed. Encoders and decoders must follow these layouts exactly. Fields appear in the order listed. All integers are unsigned. All multibyte integers use network byte order (big-endian).

## Primitive types

| Type | Encoding |
|---|---|
| `u8` | One byte |
| `u32` | Four bytes, big-endian |
| `u64` | Eight bytes, big-endian |
| Byte string | `u32 byte_length || bytes` |
| String | `u32 utf8_byte_length || UTF-8 bytes` |

Strings must be valid shortest-form UTF-8. Overlong forms, surrogate code points, invalid continuation bytes, truncated sequences, and code points above U+10FFFF are rejected. Byte strings and strings larger than `UINT32_MAX` are rejected. Readers receive an explicit maximum field size, reject truncated fields and trailing bytes when a complete object is expected, and do not advance their cursor on a failed field read.

## Hash inputs

Each hash preimage is encoded with the same primitive writer:

| Hash | Field order |
|---|---|
| Leaf | `String("LEAF") || String(fid) || u64(version) || u64(index) || ByteString(shard)` |
| Internal node | `String("NODE") || ByteString(left_hash) || ByteString(right_hash)` |

`fid` is a UTF-8 string. Hashes are exactly 32 bytes. The hash function is SHA-256 through OpenSSL EVP. Odd Merkle nodes are promoted unchanged and do not receive a synthetic sibling.

## Known-answer vectors

SHA-256 of the empty byte sequence:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Leaf hash for `fid="fid"`, `version=1`, `index=2`, and `shard=00ff`:

```text
3a3b697e25bd671554f6644923e05fb63fe90782386eafa5a6572046990e17e1
```

Node hash for two all-zero 32-byte child hashes:

```text
59b4e7c1a11063bce648212a681a10859537365e7cba7fcee7c684258876e435
```
