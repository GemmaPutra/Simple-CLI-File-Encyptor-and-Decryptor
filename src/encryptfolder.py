import pathlib
from typing import Self
from cryptography.fernet import Fernet
from encryptfile import FileCrypter


class FolderCrypter:
    def __init__(
        self, _path: pathlib.Path | None = None, /, *, key: bytes | None = None
    ) -> Self:
        if not isinstance(_path, pathlib.Path) and _path is not None:
            raise ValueError("wrong type value, only accept 'Path'")
        if not isinstance(key, bytes) and key is not None:
            raise ValueError("wrong type value, only accept 'bytes'")

        self.path = _path
        self.is_generated = key is None
        self.key = key if key is not None else Fernet.generate_key()
        self.filecrypter = FileCrypter(self.key)

    def encrypt(self, *_files: tuple[pathlib.Path, ...]) -> None:
        if all(not isinstance(_file, pathlib.Path) for _file in _files) and _files:
            raise ValueError("there is wrong type value, only accept 'Path'")

        if _files:
            for file_ in _files:
                self.filecrypter.encrypt(file_)
        else:
            if self.path is not None:
                for file_ in [f.absolute() for f in self.path.iterdir() if f.is_file()]:
                    self.filecrypter.encrypt(file_)
            else:
                raise ValueError("there is not target path")

    def decrypt(
        self, *_files: tuple[pathlib.Path, ...]
    ) -> tuple[pathlib.Path, ...] | None:
        if all(not isinstance(_file, pathlib.Path) for _file in _files) and _files:
            raise ValueError("there is wrong type value, only accept 'Path'")
        undecrypted_file = []

        if _files:
            for file_ in _files:
                res = self.filecrypter.decrypt(file_)

                if not res:
                    undecrypted_file.append(file_)
        else:
            if self.path is not None:
                for file_ in [f.absolute() for f in self.path.iterdir() if f.is_file()]:
                    res = self.filecrypter.decrypt(file_)

                    if not res:
                        undecrypted_file.append(file_)

            else:
                raise ValueError("there is not target path")

        return tuple(undecrypted_file)


if __name__ == "__main__":
    placeholder_key = b"IVV7RH8_YI4XRyyGaJ6s7N8IpT7BPuVYpGpRFBFmr60="
