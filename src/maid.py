from typing import Any
from enum import Enum, auto

class CryptMethod(Enum):
    Encrypt = auto()
    Decrypt = auto()

class FailedReason(Enum):
    NonReadable = auto()
    NonWritable = auto()
    EmptyFile = auto()
    InvalidKeyOrUnencrypted = auto()

class NotAPathObject(ValueError):
    pass

class NotAFileObject(NotADirectoryError):
    pass

class ExceededLimit(ValueError):
    pass

class EmptyKeyFile(Exception):
    pass

def save_index(_list: list[Any], _find: Any, /) -> int:
    try:
        index = _list.index(_find)
    except ValueError as _:
        return -1
    else:
        return index
