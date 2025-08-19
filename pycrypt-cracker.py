#!/usr/bin/env python3

# Simple PyCrypt Cracker - Automatically cracks .pycrypt files in current directory

import os
import hashlib
import struct
from pathlib import Path

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback colors for terminals that support ANSI
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        RESET_ALL = '\033[0m'

class SimpleCracker:
    def __init__(self):
        self.default_key = hashlib.sha256(b'default_secret').digest()
        # Don't load keywords here - we'll do it after showing ASCII art
        self.keywords = []
        
    def load_keywords(self):
        # Load passwords from keywords.txt file
        keywords = []
        
        # Try to load from keywords.txt
        if Path("keywords.txt").exists():
            try:
                with open("keywords.txt", "r", encoding="utf-8") as f:
                    keywords = [line.strip() for line in f if line.strip()]
                print(f"{Fore.CYAN}Loaded {Fore.WHITE}{len(keywords)}{Fore.CYAN} keywords from keywords.txt{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error loading keywords.txt: {e}{Style.RESET_ALL}")
        else:
            # Default keywords if no file exists
            keywords = [
                '', 'password', '123456', 'admin', 'root', 'user', 'test',
                'secret', 'key', 'pass', '123', 'abc', 'qwerty', 'letmein',
                'welcome', 'login', 'master', 'admin123', 'password123', 'okay'
            ]
            print(f"{Fore.YELLOW}No keywords.txt found, using default keywords{Style.RESET_ALL}")
            
            # Create keywords.txt with default values
            try:
                with open("keywords.txt", "w", encoding="utf-8") as f:
                    for keyword in keywords:
                        f.write(keyword + "\n")
                print(f"{Fore.GREEN}Created keywords.txt with default keywords{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Could not create keywords.txt: {e}{Style.RESET_ALL}")
        
        return keywords
    
    def find_pycrypt_files(self):
        # Find all .pycrypt files in current directory
        current_dir = Path(".")
        pycrypt_files = list(current_dir.glob("*.pycrypt"))
        return pycrypt_files
    
    def crack_file(self, file_path):
        # Crack a single .pycrypt file
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}\nCracking: {Fore.WHITE}{file_path.name}{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            if not content.startswith(b'PYCRYPT'):
                print(f"{Fore.RED}Not a valid .pycrypt file{Style.RESET_ALL}")
                return False
            
            # Parse header
            pos = 7
            version = content[pos]
            pos += 1
            has_password = content[pos]
            pos += 1
            
            if has_password:
                pass_hash = content[pos:pos + 32]
                pos += 32
                print(f"{Fore.YELLOW}\nFile Has Password (Not Blank){Style.RESET_ALL}")
                print(f"{Fore.CYAN}Trying {Fore.WHITE}{len(self.keywords)}{Fore.BLUE} keywords...{Style.RESET_ALL}\n")
                
                # Try each keyword
                for i, keyword in enumerate(self.keywords, 1):
                    print(f"  {Fore.CYAN}[{i:2d}/{len(self.keywords):2d}]{Style.RESET_ALL} Trying: '{Fore.WHITE}{keyword if keyword else '(empty)'}{Style.RESET_ALL}'")
                    
                    # Check password hash
                    computed_hash = hashlib.sha256(keyword.encode()).digest()
                    if computed_hash == pass_hash:
                        print(f"  {Fore.GREEN}{Style.BRIGHT}\nPassword found: '{keyword if keyword else '(empty)'}'{Style.RESET_ALL}")
                        
                        # Decrypt with found password
                        key = hashlib.sha256(keyword.encode()).digest()
                        encrypted_part = content[pos:]
                        decrypted = self._xor_decrypt(encrypted_part, key)
                        
                        # Extract and save file
                        if self._save_decrypted_file(file_path, decrypted):
                            return True
                        break
                else:
                    print(f"  {Fore.RED}No password match found{Style.RESET_ALL}")
                    return False
            else:
                print(f"{Fore.GREEN}No password protection - using default key{Style.RESET_ALL}")
                
                # Decrypt with default key
                encrypted_part = content[pos:]
                decrypted = self._xor_decrypt(encrypted_part, self.default_key)
                
                # Extract and save file
                if self._save_decrypted_file(file_path, decrypted):
                    return True
                
        except Exception as e:
            print(f"{Fore.RED}Error cracking file: {e}{Style.RESET_ALL}")
            return False
        
        return False
    
    def _xor_decrypt(self, data, key):
        # Decrypt data using XOR
        key_len = len(key)
        return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    
    def _save_decrypted_file(self, original_path, decrypted):
        # Extract and save the decrypted file
        try:
            dec_pos = 0
            
            # Extract filename length
            if len(decrypted) < 2:
                print(f"  {Fore.RED}Invalid decrypted data{Style.RESET_ALL}")
                return False
            name_len = struct.unpack('>H', decrypted[dec_pos:dec_pos + 2])[0]
            dec_pos += 2
            
            # Extract filename
            if len(decrypted) < dec_pos + name_len:
                print(f"  {Fore.RED}Invalid decrypted data{Style.RESET_ALL}")
                return False
            name = decrypted[dec_pos:dec_pos + name_len].decode('utf-8')
            dec_pos += name_len
            
            # Extract extension length
            if len(decrypted) < dec_pos + 2:
                print(f"  {Fore.RED}Invalid decrypted data{Style.RESET_ALL}")
                return False
            ext_len = struct.unpack('>H', decrypted[dec_pos:dec_pos + 2])[0]
            dec_pos += 2
            
            # Extract extension
            if len(decrypted) < dec_pos + ext_len:
                print(f"  {Fore.RED}Invalid decrypted data{Style.RESET_ALL}")
                return False
            ext = decrypted[dec_pos:dec_pos + ext_len].decode('utf-8')
            dec_pos += ext_len
            
            # Extract original data
            if len(decrypted) < dec_pos:
                print(f"  {Fore.RED}Invalid decrypted data{Style.RESET_ALL}")
                return False
            original_data = decrypted[dec_pos:]
            
            # Create output filename
            if ext:
                output_filename = f"{name}.{ext}"
            else:
                output_filename = name
            
            # Save file
            with open(output_filename, 'wb') as f:
                f.write(original_data)
            
            print(f"  {Fore.GREEN}Saved: {Fore.WHITE}{output_filename}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"  {Fore.RED}Error saving file: {e}{Style.RESET_ALL}")
            return False
    
    def auto_crack_all(self):
        # Automatically find and crack all .pycrypt files
        # ASCII Art Header
        ascii_art = """
    ▄███████▄ ▄██   ▄    ▄████████    ▄████████ ▄██   ▄      ▄███████▄     ███     
   ███    ███ ███   ██▄ ███    ███   ███    ███ ███   ██▄   ███    ███ ▀█████████▄ 
   ███    ███ ███▄▄▄███ ███    █▀    ███    ███ ███▄▄▄███   ███    ███    ▀███▀▀██ 
   ███    ███ ▀▀▀▀▀▀███ ███         ▄███▄▄▄▄██▀ ▀▀▀▀▀▀███   ███    ███     ███   ▀ 
▀█████████▀  ▄██   ███ ███        ▀▀███▀▀▀▀▀   ▄██   ███ ▀█████████▀      ███     
   ███        ███   ███ ███    █▄  ▀███████████ ███   ███   ███            ███     
   ███        ███   ███ ███    ███   ███    ███ ███   ███   ███            ███     
  ▄████▀       ▀█████▄  ████████▀    ███    ███  ▀█████▀   ▄████▀         ▄████▀   
                                      ███    ███        Cracker :)                            
         """
        print(f"{Fore.CYAN}{ascii_art}{Style.RESET_ALL}")
        
        # Load keywords after showing ASCII art
        self.keywords = self.load_keywords()
        
        # Find .pycrypt files
        pycrypt_files = self.find_pycrypt_files()
        
        if not pycrypt_files:
            print(f"{Fore.YELLOW}No .pycrypt files found in current directory{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}Found {Fore.WHITE}{len(pycrypt_files)}{Fore.CYAN} .pycrypt file(s){Style.RESET_ALL}")
        
        # Crack each file
        success_count = 0
        print(f"\n{Fore.BLUE}Starting to crack files...{Style.RESET_ALL}")
        for file_path in pycrypt_files:
            if self.crack_file(file_path):
                success_count += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        if success_count > 0:
            print(f"{Fore.GREEN}{Style.BRIGHT}Cracking Complete: {Fore.WHITE}{success_count}/{len(pycrypt_files)}{Fore.GREEN} files cracked{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Decrypted files saved to current directory{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}CRACKING COMPLETE: {Fore.WHITE}{success_count}/{len(pycrypt_files)}{Fore.RED} files cracked{Style.RESET_ALL}")
            print(f"{Fore.RED}No files were successfully cracked{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def main():
    # Main function to run the cracker
    cracker = SimpleCracker()
    cracker.auto_crack_all()

if __name__ == "__main__":
    main()
