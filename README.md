# 🐝 Stinger Password Generator

A colorful, terminal-based password generator built in Python.

### ⚙️ Features
- Strong random passwords (default 64 chars)
- Optional encryption with passphrase (Fernet)
- Decrypt and preview with file info (timestamps)
- Masked or hashed previews for safe viewing
- Fancy terminal UI powered by [Rich](https://github.com/Textualize/rich)

### 💻 Usage
```bash
python3 pwgen.py gen -n 5 -o secrets.bin --encrypt
python3 pwgen.py decrypt --in secrets.bin



pip install cryptography rich




