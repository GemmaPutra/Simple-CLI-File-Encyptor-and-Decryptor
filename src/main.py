import sys
import pathlib

import maid
from crypter import FilesCrypter, wordkey, filecrypt
from maid import  FailedReason, CryptMethod, save_index


common_help = """\
METHOD

arguments :
METHOD - encrypt (-e) or decrypt (-d)
"""
method_help = """\
{} [-k | --key KEY_FILE | KEY] | [FOLDER | *FILES]

argument :
KEY_FILE | KEY - key or file contain key
FOLDER | FILES - folder path or any amount of files

options  :
-k | --key     - key flag to indicate inserting a key, the key can be a word or actual key
"""


def main(argv: list[str]) -> None:
    help_prompt = ["-h", "--help"]
    crypt_method = None
    key_indexes = None
    key = None
    crypt = None
    files_path = None

    _, *args = argv

    if not args or args[0] in help_prompt:
        print(common_help)
        quit(0)

    match args:
        case ["encrypt" | "-e", *args]:
            if args[0] in help_prompt:
                print(method_help.format("encrypt"))
                quit(0)

            crypt_method = CryptMethod.Encrypt
        case ["decrypt" | "-d", *args]:
            if args[0] in help_prompt:
                print(method_help.format("decrypt"))
                quit(0)

            crypt_method = CryptMethod.Decrypt
        case _:
            print("method is required")
            quit(-1)

    if save_index(args, "-k") >= 0 and save_index(args, "--key") >= 0:
        print("use one options at a time")
        quit(0)
    elif save_index(args, "-k") >= 0:
        key_indexes = args.index("-k")
    elif save_index(args, "--key") >= 0:
        key_indexes = args.index("--key")

    if key_indexes is not None:
        try:
            _, keyp = args.pop(key_indexes), args.pop(key_indexes)
        except IndexError as _:
            print("provide some argument to option")
            quit(0)

        try:
            key = FilesCrypter.key_from_file(pathlib.Path(keyp).absolute())
        except maid.NotAFileObject as _:
            print("path is not a file")
            quit(-1)
        except maid.EmptyKeyFile as _:
            print("file is empty")
            quit(-1)
        except FileNotFoundError as _:
            key = wordkey(keyp)

    if not args:
        print("empty argument")
        quit(-1)

    if len(args) == 1:
        path = pathlib.Path(args[-1]).absolute()

        if path.is_dir() and path.exists():
            files_path = tuple([f.absolute() for f in path.iterdir() if f.is_file()])
        else:
            files_path = path,
    else:
        files_path = tuple([pathlib.Path(f).absolute() for f in args])

    try:
        with filecrypt(key) as crypter:
            for file in files_path:
                crypter.files = file

            match crypt_method:
                case CryptMethod.Encrypt:
                    crypter.encrypt()
                case CryptMethod.Decrypt:
                    crypter.decrypt()

            crypt = crypter
    except maid.NotAPathObject as _:
        print("broken scripts :(")
        quit(-1)
    except FileNotFoundError as _:
        print("there is a file that doesn't exist")
        quit(-1)
    except maid.NotAFileObject as _:
        print("some path is not valid file")
        quit(-1)
    finally:
        for failed_file in crypt.failed_files.items():
            match failed_file:
                case [file, FailedReason.NonReadable]:
                    print(f"{file.name!r} is not readable")
                case [file, FailedReason.NonWritable]:
                    print(f"{file.name!r} is not writable")
                case [file, FailedReason.EmptyFile]:
                    print(f"{file.name!r} is empty")
                case [file, FailedReason.InvalidKeyOrUnencrypted]:
                    print(f"{file.name!r} is might be unencrypted yet or using invalid key")

    if crypt.is_generated:
        crypt.make_key_file()

if __name__ == "__main__":
    main(sys.argv)