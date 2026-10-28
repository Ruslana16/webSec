# Secure Web-Based File Encryption and Management System

## Overview

This project is a secure web application that allows authenticated users to upload, encrypt, store, download, decrypt and delete files.

The application was created for the Web Application Security course.

## Features

- User registration
- User login and logout
- Password hashing
- Secure session management
- CSRF protection
- Server-side file encryption
- Server-side file decryption
- User-specific access control
- File upload and deletion
- HTTPS/TLS development setup
- 10 MB upload limit

## Technologies

- Python
- Flask
- SQLite
- Werkzeug
- Cryptography / Fernet
- Flask-WTF
- HTML
- CSS

## Security Features

### Password Hashing

Passwords are never stored in plaintext.

Werkzeug `generate_password_hash()` is used when an account is created, and `check_password_hash()` is used during login.

### Secure Sessions

Flask sessions are configured with:

- Secure cookies
- HttpOnly cookies
- SameSite=Lax

### CSRF Protection

POST requests are protected with Flask-WTF CSRF tokens.

### File Encryption

Uploaded files are encrypted on the server using Fernet authenticated symmetric encryption before being stored.

Only the encrypted version is stored in the `storage` directory.

### File Decryption

When an authenticated user downloads a file, the server decrypts it and returns the original file.

### Access Control

Each file is associated with its owner.

The server checks both the file ID and the authenticated user ID before allowing download or deletion.

### TLS

The development application runs over HTTPS using a self-signed TLS certificate.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Ruslana16/webSec.git
cd webSec
