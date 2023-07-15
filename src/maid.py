from typing import Any
from enum import Enum, auto


class CryptMethod(Enum):
    Encrypt = auto()
    Decrypt = auto()


def save_index(_list: list[Any], _find: Any, /) -> int:
    try:
        index = _list.index(_find)
    except ValueError as _:
        return -1
    else:
        return index
