import sys
import pathlib
from encryptfile import FileCrypter
from encryptfolder import FolderCrypter
from passphrase import phrase_key
from maid import CryptMethod, save_index

help_prompt = """\
crypt METHOD {[-h | --help] | {[-k | --key] KEY}} *FILES

arguments :
    METHOD - either 'encrypt' or 'decrypt'
    KEY    - the key provided can be a word or a file that contain a key
    FILES  - can be an array of files, single folder or a single file

options   :
    [-h | --help] - help options
    [-k | --key]  - key input options
"""

def main() -> None:
    _, *args = sys.argv
    help_opt = "-h", "--help"
    method = None
    crypter = None
    path = None
    paths = None
    key = None
    key_indexes = None
    decrypter_res = []
    decryptor_ending = "\n"

    if any(hc in args for hc in help_opt):
        print(help_prompt)
        quit(-1)

    match args:
        case ["encrypt" | "-e", *args]:
            method = CryptMethod.Encrypt
        case ["decrypt" | "-d", *args]:
            method = CryptMethod.Decrypt
        case []:
            print(help_prompt)
            quit(-1)
        case _:
            print("wrong argument")

    if save_index(args, "-k") >= 0 and save_index(args, "--key") >= 0:
        print("use one options at a time")
        quit(0)
    elif save_index(args, "-k") >= 0:
        key_indexes = args.index("-k")
    elif save_index(args, "--key") >= 0:
        key_indexes = args.index("--key")

    if key_indexes is not None:
        try:
            _, key = args.pop(key_indexes), args.pop(key_indexes)
        except IndexError as _:
            print("provide some argument to option")
            quit(0)

        kpath = pathlib.Path(key).absolute()

        if kpath.exists():
            with kpath.open("rb") as kp:
                if not kp.readable():
                    print("file cannot be opened")
                    quit(0)
                key = kp.read()
        else:
            key = phrase_key(key)

    if not args:
        print("lack argument at least 1 or more")
        quit(0)

    try:
        if len(args) == 1:
            path = pathlib.Path(args[0]).absolute()

            if not path.exists():
                print("file does not exist")
                quit(0)

            if path.is_dir():
                crypter = FolderCrypter(path, key=key)

                if not (files := [f_ for f_ in path.iterdir() if f_.is_file()]):
                    if method is CryptMethod.Encrypt:
                        print(f"'{len(files)}' file succesfully encrypted")
                    elif method is CryptMethod.Decrypt:
                        print(f"'{len(files)}' file being decrypted")
                    else:
                        print("wrong method")
                        quit(0)
                    quit(1)
            else:
                crypter = FileCrypter(key)
        elif len(args) > 1:
            paths = [pathlib.Path(file_) for file_ in args]

            if any(not f_.exists() for f_ in paths):
                print(paths)
                print("there is a file that does not exist")
                quit(0)
            if any(f_.is_dir() for f_ in paths): # might implement this feature later on
                print("cannot encrypt a folder with other files")
                quit(0)

            crypter = FolderCrypter(key=key)
        else:
            print("lack argument at least 1 or more")
            quit(0)
    except KeyError as _:
        print("invalid key for encryption/decryption")
        quit(0)

    if method is CryptMethod.Encrypt:
        if isinstance(crypter, FolderCrypter):
            if paths is not None:
                crypter.encrypt(*paths)

                print(f"'{len(paths)}' file succesfully encrypted")
            else:
                print(f"'{len([f_ for f_ in path.iterdir() if f_.is_file()])}' file succesfully encrypted")
                crypter.encrypt()
        else:
            crypter.encrypt(path)
            print(f"'1' file succesfully encrypted")
    elif method is CryptMethod.Decrypt:
        if isinstance(crypter, FolderCrypter):
            if paths is not None:
                decrypter_res = crypter.decrypt(*paths)

                if decrypter_res:
                    decryptor_ending = ", "
                print(f"'{len(paths) - len(decrypter_res)}' file succesfully decrypted", end=decryptor_ending)
            else:
                decrypter_res = crypter.decrypt()

                if decrypter_res:
                    decryptor_ending = ", "
                print(f"'{len([f_ for f_ in path.iterdir() if f_.is_file()]) - len(decrypter_res)}' file succesfully decrypted", end=decryptor_ending)
        else:
            decrypter_res = crypter.decrypt(path)

            if not decrypter_res:
                decryptor_ending = ", "
            print(f"'{1 if decrypter_res else 0}' file succesfully decrypted", end=decryptor_ending)

            if not decrypter_res:
                print("cannot decrypt '1' file(s), the files might be empty, use invalid key or the file has not been encrypted yet")
    else:
        print("wrong method")
        quit(0)

    if crypter.is_generated:
        path = path if path is not None else paths[0]

        key_file_path = path.parent
        with key_file_path.with_name(f"key ({f'{path.name}' if paths is None else f'{path.name}, ...'}).txt").open("wb") as kfp:
            kfp.write(crypter.key)

if __name__ == "__main__":
    main()

# still have bug when decrypting multiple file, the prompt suggesting there is only one file and it won't decrypting it