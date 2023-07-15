import pathlib
from typing import Self, TypeVar
from cryptography.fernet import Fernet
import cryptography.fernet

FernetOrKey = TypeVar("FernetOrKey", Fernet, bytes)


class FileCrypter:
    def __init__(self, _object: FernetOrKey | None = None, /) -> Self:
        self.key = None
        self.is_generated = False

        try:
            if isinstance(_object, bytes):
                self.key = _object
                self.crypter = Fernet(self.key)
            elif isinstance(_object, Fernet):
                self.crypter = _object
            elif _object is None:
                self.is_generated = True
                self.key = Fernet.generate_key()
                self.crypter = Fernet(self.key)
            else:
                raise ValueError("wrong type value, only accept 'Fernet' or 'bytes'")
        except ValueError as ferve:
            raise KeyError("wrong key") from ferve

    def is_storing_key(self) -> bool:
        return self.key is not None

    def encrypt(
        self, _path: pathlib.Path, /, *, target: pathlib.Path | None = None
    ) -> None:
        _path = _path.absolute()
        if not isinstance(_path, pathlib.Path):
            raise ValueError("wrong type value, only accept 'Path'")
        elif not _path.exists():
            raise FileNotFoundError("file does not exist")
        elif not _path.is_file():
            raise ValueError("file is not a file")
        if target is not None:
            target = target.absolute()

            if not isinstance(target, pathlib.Path):
                raise ValueError("wrong type value, only accept 'Path'")

            try:
                target.touch(exist_ok=False)
            except FileExistsError as err_fer:
                raise FileExistsError(
                    "there is already file with the same name"
                ) from err_fer
        content = None

        with _path.open("rb") as readfile:
            if not readfile.readable():
                raise ValueError("file cannot be read into")

            content = readfile.read()

        if content == bytes("".encode()):
            return None

        if target is not None:
            with target.open("wb") as writefile:
                if not writefile.writable():
                    raise ValueError("file cannot be write into")

                writefile.write(self.crypter.encrypt(content))
        else:
            with _path.open("wb") as writefile:
                if not writefile.writable():
                    raise ValueError("file cannot be write into")

                writefile.write(self.crypter.encrypt(content))

    def decrypt(
        self, _path: pathlib.Path, /, *, target: pathlib.Path | None = None
    ) -> bool:
        _path = _path.absolute()

        if not isinstance(_path, pathlib.Path):
            raise ValueError("wrong type value, only accept 'Path'")
        elif not _path.exists():
            raise FileNotFoundError("file does not exist")
        elif not _path.is_file():
            raise ValueError("file is not a file")
        if target is not None:
            target = target.absolute()

            if not isinstance(target, pathlib.Path):
                raise ValueError("wrong type value, only accept 'Path'")

            try:
                target.touch(exist_ok=False)
            except FileExistsError as err_fer:
                raise FileExistsError(
                    "there is already file with the same name"
                ) from err_fer
        content = None

        with _path.open("rb") as readfile:
            if not readfile.readable():
                raise ValueError("file cannot be read into")

            content = readfile.read()

        if content == bytes("".encode()):
            return False

        if target is not None:
            with target.open("wb") as writefile:
                if not writefile.writable():
                    raise ValueError("file cannot be write into")
                writefile.write(self.crypter.decrypt(content))
        else:
            with _path.open("wb") as writefile:
                if not writefile.writable():
                    raise ValueError("file cannot be write into")

                try:
                    writefile.write(self.crypter.decrypt(content))
                except cryptography.fernet.InvalidToken as _:
                    writefile.write(content)
                    return False
                else:
                    return True


if __name__ == "__main__":
    placeholder_key = b"IVV7RH8_YI4XRyyGaJ6s7N8IpT7BPuVYpGpRFBFmr60="
