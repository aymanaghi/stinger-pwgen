#!/usr/bin/env python3
"""
pwgen.py — Fancy Random Password Generator + encrypted file save + preview + file-info

Features:
 - Default length 64
 - Preview generated passwords before saving
 - --mask to mask passwords on-screen (show last 4 chars)
 - --show-hashes to show SHA-256 fingerprint instead of raw passwords
 - Confirm before writing
 - Encrypts with cryptography (Fernet + PBKDF2)
 - Decrypt shows filename + creation & modification dates
"""

import argparse
import base64
import datetime
import hashlib
import os
import secrets
import string
import sys
from getpass import getpass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# cryptography
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception:
    console.print("[bold red]Missing dependency:[/bold red] cryptography")
    console.print("Install with: [cyan]pip install cryptography[/cyan]")
    sys.exit(1)

MAGIC_HEADER = b"PWGENv1\n"
SALT_SIZE = 16
KDF_ITERS = 390_000  # strong-ish default


def derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    key = kdf.derive(password)
    return base64.urlsafe_b64encode(key)


def generate_password(length: int) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?|~"
    return ''.join(secrets.choice(chars) for _ in range(length))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def mask_pw(pw: str, show_last: int = 4) -> str:
    if len(pw) <= show_last:
        return pw
    return "*" * (len(pw) - show_last) + pw[-show_last:]


def encrypt_text(text_bytes: bytes, passphrase: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key_from_password(passphrase.encode('utf-8'), salt)
    f = Fernet(key)
    token = f.encrypt(text_bytes)
    return MAGIC_HEADER + salt + token


def decrypt_blob(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC_HEADER):
        raise ValueError("Invalid file format.")
    salt = blob[len(MAGIC_HEADER):len(MAGIC_HEADER) + SALT_SIZE]
    token = blob[len(MAGIC_HEADER) + SALT_SIZE:]
    key = derive_key_from_password(passphrase.encode('utf-8'), salt)
    f = Fernet(key)
    return f.decrypt(token)


def show_preview(passwords, mask=False, show_hashes=False):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", width=3, justify="right")
    table.add_column("Password / Hash", overflow="fold")

    for i, pw in enumerate(passwords, start=1):
        if show_hashes:
            table.add_row(str(i), sha256_hex(pw))
        elif mask:
            table.add_row(str(i), mask_pw(pw))
        else:
            table.add_row(str(i), pw)

    title = "[bold yellow]Preview — Generated Passwords[/bold yellow]"
    console.print(Panel(table, title=title, expand=False))


def cmd_gen(args):
    # generate
    passwords = [generate_password(args.length) for _ in range(args.count)]

    # show preview
    show_preview(passwords, mask=args.mask, show_hashes=args.show_hashes)

    # if user didn't ask to save, stop here
    if not args.out:
        console.print("[green]No output file requested — generation finished.[/green]")
        return

    # confirm before write: if hashing view is enabled, warn that saving plaintext will expose them
    if args.show_hashes:
        console.print("[yellow]Note:[/yellow] you're viewing SHA256 hashes. Saving plaintext will write the real passwords to disk.")
    confirm = Confirm.ask(f"Save {len(passwords)} passwords to '{args.out}'? (this will {'encrypt' if args.encrypt else 'write plaintext to'} the file)")

    if not confirm:
        console.print("[red]Aborted — file not written.[/red]")
        return

    joined = "\n".join(passwords) + "\n"

    if args.encrypt:
        passphrase = getpass("Enter a passphrase to encrypt the file: ")
        passphrase2 = getpass("Confirm passphrase: ")
        if passphrase != passphrase2:
            console.print("[red]Passphrases don't match. abort.[/red]")
            return
        with Progress(SpinnerColumn(), TextColumn("[cyan]Encrypting...")) as progress:
            progress.add_task("encrypting", total=None)
            blob = encrypt_text(joined.encode('utf-8'), passphrase)
            with open(args.out, "wb") as f:
                f.write(blob)
        console.print(f"[bold green]✅ Encrypted file saved to [cyan]{args.out}[/cyan][/bold green]")
    else:
        with open(args.out, "w") as f:
            f.write(joined)
        console.print(f"[bold green]💾 Plaintext file saved to [cyan]{args.out}[/cyan][/bold green]")


def cmd_decrypt(args):
    if not os.path.exists(args.infile):
        console.print(f"[red]File not found:[/red] {args.infile}")
        sys.exit(2)

    # file metadata
    file_stats = os.stat(args.infile)
    try:
        created = datetime.datetime.fromtimestamp(file_stats.st_ctime)
    except Exception:
        created = None
    try:
        modified = datetime.datetime.fromtimestamp(file_stats.st_mtime)
    except Exception:
        modified = None

    created_str = created.strftime('%Y-%m-%d %H:%M:%S') if created else "Unknown"
    modified_str = modified.strftime('%Y-%m-%d %H:%M:%S') if modified else "Unknown"

    file_info = f"[cyan]{args.infile}[/cyan]\nCreated: [yellow]{created_str}[/yellow]\nModified: [yellow]{modified_str}[/yellow]"

    blob = open(args.infile, "rb").read()
    passphrase = getpass("Enter passphrase: ")

    try:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Decrypting...")) as progress:
            progress.add_task("decrypting", total=None)
            plain = decrypt_blob(blob, passphrase)
    except InvalidToken:
        console.print("[red]Invalid passphrase or file.[/red]")
        sys.exit(3)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(3)

    text = plain.decode('utf-8')
    lines = [l for l in text.splitlines() if l.strip()]

    console.print(
        Panel(
            file_info,
            title="[bold green]🔓 File Info[/bold green]",
            expand=False,
            border_style="green"
        )
    )

    show_preview(lines, mask=False, show_hashes=False)
    console.print(f"[green]Total passwords: {len(lines)}[/green]")


def build_parser():
    p = argparse.ArgumentParser(prog="pwgen", description="Random password generator + confirm-before-save")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate passwords")
    g.add_argument("--count", "-n", type=int, default=1, help="how many passwords to create")
    g.add_argument("--length", "-l", type=int, default=64, help="length of each password")
    g.add_argument("--out", "-o", type=str, default=None, help="save passwords to file (plaintext if --encrypt not used)")
    g.add_argument("--encrypt", action="store_true", help="encrypt the output file (will prompt for passphrase)")
    g.add_argument("--mask", action="store_true", help="mask passwords when previewing (show only last 4 chars)")
    g.add_argument("--show-hashes", action="store_true", help="show SHA256 hashes instead of raw passwords in preview")

    d = sub.add_parser("decrypt", help="decrypt a file produced by this tool")
    d.add_argument("--in", dest="infile", required=True, help="encrypted file to decrypt")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd == "gen":
        cmd_gen(args)
    elif args.cmd == "decrypt":
        cmd_decrypt(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    console.print("[bold yellow]🐝 Stinger Password Generator — preview mode enabled 🐝[/bold yellow]\n")
    main()
