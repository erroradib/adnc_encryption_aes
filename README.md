# Secure Message Encryption and Decryption Scripts
- Author: Adnan Adib
Welcome to the ultimate skibidi of encryption and decryption! 🎉 These Python scripts are here to keep your messages safe and sound, just like your favorite grimace shake from McDonald's. Using top-tier AES (Advanced Encryption Standard) and Scrypt key derivation, these scripts ensure your secrets are more secure than ever. Encrypt your messages with ease and decrypt them just as effortlessly. Perfect for all your secure communication needs. Keep your data safe, stay cool, and enjoy the tech ride! 😎🔐


## Encryption
To encrypt a message, run the encryption.py script with the message and password as arguments:
```bash
python encryption.py "your_message_here" "secret_key"
```

## Decryption
To decrypt a message, run the decryption.py script with the encrypted message and password as arguments:
```bash
python decryption.py "your_encrypted_message_here" "secret_key"
```

## Exmple
Encrypt a Message
```bash
python encryption.py "What the Sigma!" "secret_key"
```
Output:
```bash
Encrypted: <base64_encrypted_message>
```
Decrypt a Message:
```bash
python decryption.py "<base64_encrypted_message>" "secret_key"
```
Output:
```bash
Decrypted: What the Sigma!
```
## Security Considerations
- Password Strength: Ensure that you use a strong password to enhance security
- Keep Keys Secure: The security of your encrypted data relies on keeping the password and salt secure
