import os
import sys
import getpass
import hashlib
import struct

YELLOW = "\033[33m"
RESET = "\033[0m"

def center_ascii(art: str) -> str:
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80

    lines = art.split('\n')
    centered_lines = []
    max_line_length = max(len(line.rstrip()) for line in lines if line.strip())

    for line in lines:
        if line.strip():
            padding = (terminal_width - len(line.rstrip())) // 2
            if padding < 0:
                padding = 0
            centered_lines.append(' ' * padding + line.rstrip())
        else:
            centered_lines.append('')
    return '\n'.join(centered_lines)

LOGO = center_ascii(r"""
   ▄███████▄ ▄██   ▄    ▄████████    ▄████████ ▄██   ▄      ▄███████▄     ███     
  ███    ███ ███   ██▄ ███    ███   ███    ███ ███   ██▄   ███    ███ ▀█████████▄ 
  ███    ███ ███▄▄▄███ ███    █▀    ███    ███ ███▄▄▄███   ███    ███    ▀███▀▀██ 
  ███    ███ ▀▀▀▀▀▀███ ███         ▄███▄▄▄▄██▀ ▀▀▀▀▀▀███   ███    ███     ███   ▀ 
▀█████████▀  ▄██   ███ ███        ▀▀███▀▀▀▀▀   ▄██   ███ ▀█████████▀      ███     
  ███        ███   ███ ███    █▄  ▀███████████ ███   ███   ███            ███     
  ███        ███   ███ ███    ███   ███    ███ ███   ███   ███            ███     
 ▄████▀       ▀█████▄  ████████▀    ███    ███  ▀█████▀   ▄████▀         ▄████▀   
                                    ███    ███                                    
""")

MAIN_MENU = center_ascii(r"""
╔═════════╗
╔════╝         ╚════╗
╔═════╝                   ╚═════╗
║          [1] Encrypt          ║
║          [2] Decrypt          ║
╚═════╗                   ╔═════╝
╚════╗         ╔════╝
╚═════════╝
""")

SUB_MENU = center_ascii(r"""
╔═════════╗
╔════╝         ╚════╗
╔═════╝                   ╚═════╗
║           [1] File            ║
║          [2] Folder           ║
╚═════╗                   ╔═════╝
╚════╗         ╔════╝
╚═════════╝
""")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def encrypt_data(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

def decrypt_data(data: bytes, key: bytes) -> bytes:
    return encrypt_data(data, key)  # XOR is symmetric

def encrypt_file(file_path: str, password: str):
    if not os.path.isfile(file_path):
        print(f"{YELLOW}File not found: {file_path}{RESET}")
        return

    has_password = bool(password)
    key = hashlib.sha256(password.encode() if has_password else b'default_secret').digest()
    pass_hash = hashlib.sha256(password.encode()).digest() if has_password else b''

    with open(file_path, 'rb') as f:
        original_data = f.read()

    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    if ext.startswith('.'):
        ext = ext[1:]
    name_bytes = name.encode('utf-8')
    ext_bytes = ext.encode('utf-8')

    header_info = struct.pack('>H', len(name_bytes)) + name_bytes + struct.pack('>H', len(ext_bytes)) + ext_bytes
    to_encrypt = header_info + original_data
    encrypted = encrypt_data(to_encrypt, key)

    plain_header = b'PYCRYPT' + b'\x01' + bytes([1 if has_password else 0]) + pass_hash
    new_path = os.path.join(os.path.dirname(file_path), name + '.pycrypt')

    with open(new_path, 'wb') as f:
        f.write(plain_header + encrypted)

    os.remove(file_path)
    print(f"{YELLOW}Encrypted: {file_path} -> {new_path}{RESET}")

def decrypt_file(file_path: str):
    if not os.path.isfile(file_path):
        print(f"{YELLOW}File not found: {file_path}{RESET}")
        return

    with open(file_path, 'rb') as f:
        content = f.read()

    if not content.startswith(b'PYCRYPT'):
        print(f"{YELLOW}Not a valid .pycrypt file: {file_path}{RESET}")
        return

    pos = 7
    version = content[pos]
    pos += 1
    if version != 1:
        print(f"{YELLOW}Unsupported version: {version}{RESET}")
        return

    has_password = content[pos]
    pos += 1

    pass_hash = b''
    if has_password:
        pass_hash = content[pos:pos + 32]
        pos += 32

    if has_password:
        input_password = getpass.getpass(f"{YELLOW}Enter password for {file_path}: {RESET}")
        computed_hash = hashlib.sha256(input_password.encode()).digest()
        if computed_hash != pass_hash:
            print(f"{YELLOW}Incorrect password!{RESET}")
            return
        key = hashlib.sha256(input_password.encode()).digest()
    else:
        key = hashlib.sha256(b'default_secret').digest()

    encrypted_part = content[pos:]
    decrypted = decrypt_data(encrypted_part, key)

    dec_pos = 0
    name_len = struct.unpack('>H', decrypted[dec_pos:dec_pos + 2])[0]
    dec_pos += 2
    name = decrypted[dec_pos:dec_pos + name_len].decode('utf-8')
    dec_pos += name_len
    ext_len = struct.unpack('>H', decrypted[dec_pos:dec_pos + 2])[0]
    dec_pos += 2
    ext = decrypted[dec_pos:dec_pos + ext_len].decode('utf-8')
    dec_pos += ext_len
    original_data = decrypted[dec_pos:]

    original_ext = '.' + ext if ext else ''
    new_path = os.path.join(os.path.dirname(file_path), name + original_ext)

    with open(new_path, 'wb') as f:
        f.write(original_data)

    os.remove(file_path)
    print(f"{YELLOW}Decrypted: {file_path} -> {new_path}{RESET}")

def encrypt_folder(folder_path: str, password: str):
    if not os.path.isdir(folder_path):
        print(f"{YELLOW}Folder not found: {folder_path}{RESET}")
        return

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            if full_path.endswith('.pycrypt'):
                continue
            encrypt_file(full_path, password)

def decrypt_folder(folder_path: str):
    if not os.path.isdir(folder_path):
        print(f"{YELLOW}Folder not found: {folder_path}{RESET}")
        return

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.pycrypt'):
                full_path = os.path.join(root, file)
                decrypt_file(full_path)

def main():
    clear_screen()
    print(f"{YELLOW}{LOGO}{RESET}")
    while True:
        print(f"{YELLOW}{MAIN_MENU}{RESET}")
        choice = input(f"{YELLOW}--> {RESET}").strip()
        if choice not in ['1', '2']:
            print(f"{YELLOW}Invalid choice!{RESET}")
            continue

        is_encrypt = choice == '1'

        clear_screen()
        print(f"{YELLOW}{LOGO}{RESET}")
        print(f"{YELLOW}{SUB_MENU}{RESET}")
        sub_choice = input(f"{YELLOW}--> {RESET}").strip()
        if sub_choice not in ['1', '2']:
            print(f"{YELLOW}Invalid choice!{RESET}")
            continue

        is_file = sub_choice == '1'

        path = input(f"{YELLOW}Enter the directory of the {'file' if is_file else 'folder'}: {RESET}").strip()

        if is_encrypt:
            password = getpass.getpass(f"{YELLOW}Enter password (leave blank for none): {RESET}")
            if is_file:
                encrypt_file(path, password)
            else:
                encrypt_folder(path, password)
        else:
            if is_file:
                decrypt_file(path)
            else:
                decrypt_folder(path)

        input(f"{YELLOW}Press Enter to continue...{RESET}")
        clear_screen()
        print(f"{YELLOW}{LOGO}{RESET}")

if __name__ == "__main__":
    main()
