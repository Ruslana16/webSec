# Checkpoint 2 Progress Note

## Project

Secure Web-Based File Encryption and Management System

## Current Status

The core functionality required for Checkpoint 2 has been implemented.

## Implemented

### Web Interface

The application includes:

- Registration
- Login
- Dashboard
- File upload
- File download
- File deletion
- Logout

### Authentication

Passwords are hashed before being stored in the SQLite database.

Authenticated sessions are used to protect application functionality.

Session cookies use Secure, HttpOnly and SameSite=Lax settings.

### File Encryption

Uploaded files are encrypted on the server before being stored.

Fernet authenticated symmetric encryption is used.

### File Decryption

When a user downloads a file, the encrypted file is decrypted on the server and returned in its original form.

### Access Control

Users can access only their own files.

The server checks both the current authenticated user ID and the requested file ID.

### CSRF Protection

POST requests are protected with CSRF tokens.

### TLS

The application runs over HTTPS in the development environment using a self-signed TLS certificate.

### Documentation

The README contains complete setup and run instructions.

## Current Limitations

This is a development prototype.

It currently uses:

- SQLite
- Local file storage
- One server-side encryption key
- A self-signed TLS certificate

## Possible Future Improvements

- Per-user encryption keys
- Rate limiting
- Audit logging
- Password change functionality
- Production deployment configuration
- Encryption key rotation
