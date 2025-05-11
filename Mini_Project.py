import os
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import dropbox
from getpass import getpass

CONFIG_FILE = "secure_storage_config.json"

class SecureCloudStorage:
    def __init__(self):
        self.key = None
        self.name_key = None
        self.salt = None
        self.dbx = None
        self.load_config()
        
    def load_config(self):
        """Load encryption config from file"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.salt = bytes.fromhex(config['salt'])
                print("✓ Loaded existing encryption configuration")
        else:
            self.salt = get_random_bytes(16)
            print("✓ Created new encryption configuration")

    def save_config(self):
        """Save encryption config to file"""
        config = {'salt': self.salt.hex()}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def derive_keys(self, password: str):
        """Derive consistent keys using stored salt"""
        self.key = hashlib.pbkdf2_hmac('sha256', 
                                      (password + "content").encode(), 
                                      self.salt, 
                                      100000)
        self.name_key = hashlib.pbkdf2_hmac('sha256', 
                                           (password + "filename").encode(), 
                                           self.salt, 
                                           100000)

    def connect_dropbox(self, token: str):
        """Initialize Dropbox connection"""
        self.dbx = dropbox.Dropbox(token)
        try:
            # Verify connection works
            self.dbx.users_get_current_account()
            print("✓ Successfully connected to Dropbox")
        except Exception as e:
            print(f"✖ Failed to connect to Dropbox: {str(e)}")
            self.dbx = None
            raise
        
    def encrypt_file(self, file_path: str):
        """Encrypt file and return (encrypted_path, encrypted_filename)"""
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)

        encrypted_filename = self.encrypt_filename(os.path.basename(file_path)) + '.enc'
        encrypted_path = os.path.join(os.path.dirname(file_path), encrypted_filename)

        with open(encrypted_path, 'wb') as f:
            f.write(iv + ciphertext)

        return encrypted_path, encrypted_filename


    def encrypt_filename(self, filename: str) -> str:
        """Encrypt filename using AES-ECB"""
        cipher = AES.new(self.name_key, AES.MODE_ECB)
        padded_name = pad(filename.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_name)
        return base64.urlsafe_b64encode(encrypted).decode().replace("=", "")

    def decrypt_filename(self, encrypted_name: str) -> str:
        """Decrypt filename"""
        cipher = AES.new(self.name_key, AES.MODE_ECB)
        encrypted = base64.urlsafe_b64decode(encrypted_name + '==')
        decrypted = cipher.decrypt(encrypted)
        return unpad(decrypted, AES.block_size).decode()

    def decrypt_file(self, encrypted_path: str) -> str:
        """Bulletproof decryption with complete diagnostics"""
        # 1. Pre-flight checks
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"Missing file: {encrypted_path}")
        
        file_size = os.path.getsize(encrypted_path)
        print(f"• File size: {file_size} bytes")
        
        # 2. Read raw data
        with open(encrypted_path, 'rb') as f:
            data = f.read()
        
        # 3. Validate structure
        MIN_SIZE = 32  # IV (16) + minimum ciphertext (16)
        if len(data) < MIN_SIZE:
            raise ValueError(f"Corrupted file: Needs {MIN_SIZE} bytes, got {len(data)}")
        
        # 4. Extract components
        iv = data[:16]
        ciphertext = data[16:]
        print(f"• IV: {iv.hex()}")
        print(f"• Ciphertext: {len(ciphertext)} bytes")
        
        # 5. Verify key
        print(f"• Key: {self.key.hex()}")
        if len(self.key) not in (16, 24, 32):
            raise ValueError("Invalid key length - must be 16/24/32 bytes")
        
        # 6. Decryption with full validation
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            
            # Manual PKCS7 unpadding with validation
            pad_byte = plaintext[-1]
            if 1 <= pad_byte <= AES.block_size:
                if all(b == pad_byte for b in plaintext[-pad_byte:]):
                    plaintext = plaintext[:-pad_byte]
                    print("• PKCS7 padding successfully removed")
                else:
                    raise ValueError("Invalid padding bytes")
            else:
                raise ValueError(f"Invalid padding byte: {pad_byte}")
            
            # 7. Validate decrypted content
            try:
                plaintext.decode('utf-8')  # Test if text file
                print("• Valid UTF-8 text detected")
            except UnicodeDecodeError:
                print("• Binary data detected")
            
            # 8. Save decrypted file
            original_name = self.decrypt_filename(os.path.basename(encrypted_path)[:-4])
            original_path = os.path.join(os.path.dirname(encrypted_path), original_name)
            
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"✓ Successfully decrypted to: {original_path}")
            return original_path
        
        except Exception as e:
            print(f"✖ Decryption failed at step: {str(e)}")
            print("\nTROUBLESHOOTING:")
            print("1. Verify EXACT same password used for both operations")
            print("2. Check config.json hasn't been modified")
            print("3. Try encrypting/decrypting a new test file")
            print("4. Compare file hashes with original upload")
            return None

    def upload_file(self):
        """Interactive file upload"""
        file_path = input("\nEnter file path to upload: ").strip('"')
        
        if not os.path.exists(file_path):
            print("✖ File not found")
            return
        
        try:
            encrypted_path, encrypted_name = self.encrypt_file(file_path)
            remote_path = '/' + encrypted_name
            
            with open(encrypted_path, 'rb') as f:
                self.dbx.files_upload(f.read(), remote_path, 
                                    mode=dropbox.files.WriteMode('overwrite'))
            
            os.remove(encrypted_path)
            print(f"✓ Uploaded as: {encrypted_name}")
            
        except Exception as e:
            print(f"✖ Upload failed: {str(e)}")
            if 'encrypted_path' in locals() and os.path.exists(encrypted_path):
                os.remove(encrypted_path)

    def download_file(self):
        """Interactive file download"""
        try:
            result = self.dbx.files_list_folder('')
            encrypted_files = [entry.name for entry in result.entries 
                             if entry.name.endswith('.enc')]
            
            if not encrypted_files:
                print("No encrypted files found")
                return
                
            print("\nAvailable files:")
            for i, name in enumerate(encrypted_files, 1):
                print(f"{i}. {name}")
            
            selection = input("Enter file number to download (0 to cancel): ")
            if selection == '0':
                print("\nCanceled")
                return
                
            selected_name = encrypted_files[int(selection)-1]
            local_path = os.path.join(os.getcwd(), selected_name)
            
            # Download
            self.dbx.files_download_to_file(local_path, '/' + selected_name)
            print(f"✓ Downloaded: {selected_name}")
            
            # Decrypt
            decrypted_path = self.decrypt_file(local_path)
            if decrypted_path:
                os.remove(local_path)
                print(f"✓ Decrypted to: {os.path.basename(decrypted_path)}")
            else:
                print("Keeping encrypted copy due to decryption failure")
                
        except Exception as e:
            print(f"✖ Error: {str(e)}")
            if 'local_path' in locals() and os.path.exists(local_path):
                os.remove(local_path)

    def delete_file(self):
        """Delete file from Dropbox"""
        try:
            result = self.dbx.files_list_folder('')
            encrypted_files = [entry.name for entry in result.entries 
                             if entry.name.endswith('.enc')]
            
            if not encrypted_files:
                print("No files to delete")
                return
                
            print("\nFiles available for deletion:")
            for i, name in enumerate(encrypted_files, 1):
                print(f"{i}. {name}")
            
            selection = input("Enter file number to delete (0 to cancel): ")
            if selection == '0':
                return
                
            selected_name = encrypted_files[int(selection)-1]
            
            confirm = input(f"PERMANENTLY delete {selected_name}? (y/n): ")
            if confirm.lower() == 'y':
                self.dbx.files_delete('/' + selected_name)
                print(f"✓ Deleted: {selected_name}")
            else:
                print("Deletion canceled")
                
        except Exception as e:
            print(f"✖ Error: {str(e)}")

def main():
    print("=== Secure Cloud Storage ===")
    storage = SecureCloudStorage()
    
    # Setup encryption
    password = getpass("Enter encryption password: ")
    storage.derive_keys(password)
    storage.save_config()
    
    # Connect to Dropbox
    while True:
        dbx_token = input("Enter Dropbox access token: ").strip()
        try:
            storage.connect_dropbox(dbx_token)
            break
        except:
            print("Please try again or press Ctrl+C to quit")
    
    # Main menu
    while True:
        print("\nMenu:")
        print("1. Upload file")
        print("2. Download file")
        print("3. Delete file")
        print("4. Exit")
        
        choice = input("Select option (1-4): ")
        
        if choice == '1':
            storage.upload_file()
        elif choice == '2':
            storage.download_file()
        elif choice == '3':
            storage.delete_file()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()