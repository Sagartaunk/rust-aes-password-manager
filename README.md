# Password Manager

This password manager uses Argon2 for password hashing and AES-GCM for encryption. It allows you to add, view, and delete passwords securely.

## Features

- **Key Generation**: Utilizes Argon2 for generating secure keys from a password and salt.
- **File Handling**: Supports loading and saving accounts from/to a JSON file.
- **Encryption/Decryption**: Uses AES-GCM for encrypting and decrypting account information.
- **CLI Interface**: Provides a simple CLI interface for user interaction.

## Dependencies

- `argon2`: For password hashing.
- `rand`: For generating random values.
- `aes-gcm`: For AES-GCM encryption.
- `hex`: For encoding and decoding hexadecimal strings.
- `serde_json`: For handling JSON serialization and deserialization.

## Functions

### `key_generator(password: String, salt: Vec<u8>) -> Key<Aes256Gcm>`
Generates a key using Argon2 from the provided password and salt.

### `load_from_file() -> std::io::Result<Vec<Aaccount>>`
Loads the accounts from the `passwords.json` file. Returns an empty vector if the file does not exist or is empty.

### `load_to_file(accounts: Vec<Aaccount>)`
Saves the provided accounts to the `passwords.json` file.

### `run()`
The main function that runs the program. Provides a menu for the user to choose from different options.

### `password_test() -> String`
Tests if the provided password is correct. If not, prompts the user to re-enter the password.

### `add_password()`
Adds a new password to the file. Encrypts the account information before saving.

### `password_view()`
Displays all stored accounts and their passwords.

### `delete_password()`
Deletes a specified account from the file.

## Usage

1. **Run the Program**: Use `cargo run` to start the program.
2. **Menu Options**:
   - `1`: Add a new password.
   - `2`: View all stored passwords.
   - `3`: Delete a specific password.
   - `4`: Exit the program.

## Example Usage

```sh
$ cargo run
1. Add Password
2. View Passwords
3. Delete Password
4. Exit
Enter your choice: 1
```

## Security

- Passwords are hashed using Argon2 before being used for key generation.
- Account information is encrypted using AES-GCM before being stored in the file.
- The key and nonce are stored in a separate `key.txt` file.

Make sure to keep your `key.txt` file secure as it is required for decrypting your account information.
