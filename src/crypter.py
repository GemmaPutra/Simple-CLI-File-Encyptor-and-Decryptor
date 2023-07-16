import base64
import pathlib
from typing import Self, Iterable
from traceback import print_tb

import cryptography.fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import maid
from maid import FailedReason

class FilesCrypter:
    def __init__(self, *, key: bytes | None = None) -> Self:
        self.is_generated = key is None
        self.key = key if key is not None else Fernet.generate_key() # just need key no need for fernet object to be passed

        try:
            self.fernet = Fernet(self.key)
        except ValueError as _:
            raise cryptography.fernet.InvalidToken("wrong key format")

        self.failed_files = {}
        self._files = []

    def __len__(self) -> int:
        return len(self._files)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc, val, trb) -> None:
        if exc is not None:
            print_tb(trb)
            raise exc(val)

    @property
    def files(self) -> tuple[pathlib.Path]:
        return tuple(self._files)

    @files.setter
    def files(self, _new_files: pathlib.Path) -> None:
        self.add_files(_new_files)


    def add_files(self, *file: Iterable[pathlib.Path]) -> None:
        if any(not isinstance(_f_, pathlib.Path) for _f_ in file):
            raise maid.NotAPathObject("there is a file that is not a path")
        if any(not _f_.exists() for _f_ in file):
            raise FileNotFoundError("there is a file that doesn't exists")
        if any(not _f_.is_file() for _f_ in file):
            raise maid.NotAFileObject("there is a file that is not a file")

        self._files.extend(file)


    def encrypt(self) -> None:
        if not self.files:
            return None

        for file in self.files:
            content: bytes = None

            with file.open("rb") as readf:
                if not readf.readable():
                    self.failed_files[file] = FailedReason.NonReadable
                    continue
                content = readf.read()

            if not content:
                self.failed_files[file] = FailedReason.EmptyFile
                continue

            with file.open("wb") as writef:
                if not writef.writable():
                    self.failed_files[file] = FailedReason.NonWritable
                    continue
                writef.write(self.fernet.encrypt(content))

    def decrypt(self) -> None:
        if not self.files:
            return None

        for file in self.files:
            content: bytes = None

            with file.open("rb") as readf:
                if not readf.readable():
                    self.failed_files[file] = FailedReason.NonReadable
                    continue

                content = readf.read()

            if not content:
                self.failed_files[file] = FailedReason.EmptyFile
                continue

            with file.open("wb") as writef:
                if not writef.writable():
                    self.failed_files[file] = FailedReason.NonWritable
                    continue
                try:
                    writef.write(self.fernet.decrypt(content))
                except cryptography.fernet.InvalidToken as _:
                    writef.write(content)
                    self.failed_files[file] = FailedReason.InvalidKeyOrUnencrypted
                    continue


    def make_key_file(self, _root: pathlib.Path | None = None, /) -> None:
        path: pathlib.Path = self.files[0].absolute().parent

        if _root is not None:
            path = _root.absolute()

        if len(self.files) < 2:
            key_filename = f"key ( {self.files[0].name} )"
        elif len(self.files) == 2:
            key_filename = f"key ( {self.files[0].name}, {self.files[-1].name} )"
        else:
            key_filename = f"key ( {self.files[0].name}, {self.files[-1].name}, ... )"

        text_suff = ".txt"
        path = path / f"{key_filename}{text_suff}"
        err_count = 0
        tpath = path

        while True:
            if err_count > 100:
                raise maid.ExceededLimit("the file exceeded limit of 100 iterations")

            try:
                with tpath.open("wb") as keyf:
                    keyf.write(self.key)
            except FileExistsError as _:
                err_count += 1
                f_name = f"{path.name} ({err_count}){text_suff}"
                tpath = path.with_name(f_name)
            else:
                break

    @staticmethod
    def key_from_file(_path: pathlib.Path, /) -> bytes:
        if not isinstance(_path, pathlib.Path):
            raise maid.NotAPathObject("file is not a path")
        if not _path.exists():
            raise FileNotFoundError("file doesn't exist")
        if not _path.is_file():
            raise maid.NotAFileObject("path is not pointing to a file")

        content_key = None

        with _path.open("rb") as keyf:
            content_key = keyf.read()

            if not content_key:
                raise maid.EmptyKeyFile("file is empty")

        return content_key


def filecrypt(_key: bytes) -> FilesCrypter:
    return FilesCrypter(key=_key)


def wordkey(_word: str, /) -> bytes:
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100_000,
            length=32,
            salt=b"]\xf3:\x17\xb4\x99\xd0\x0f\x0cB@\x06o\xc8Me",  # hard coded the os.urandom() for consistencies
            backend=default_backend(),
        ).derive(bytes(_word.encode()))
    )


if __name__ == "__main__":
    placeholder_key = b"IVV7RH8_YI4XRyyGaJ6s7N8IpT7BPuVYpGpRFBFmr60="