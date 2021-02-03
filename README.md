# Firmware for The Tablet Communication System

The Tablet is a secure communication device designed according the NSAR (Non-Symmetric Accessibility Relation) security policy.

## How it works

All data handling components are effectively air-gapped from upstream components to prevent information leakage to devices connected upstream. Asymmetric encryption masks every message sent, and decryption is handled in such a way as to guarantee plaintext is hardware inaccessible to any networked device.

## Installation
- Clone this repository.
- Clone Cryptopp into the root of this repository.
- Install Cryptopp by:
```bash
cd path/to/this/repository/
cd cryptopp/
make
sudo make install
```
### Optional

For contributors to the project do this before making your first commit:

- Install pre-commit
```bash
sudo apt install pre-commit
cd path/to/this/repository/
pre-commit install
```
## How to Compile
- To compile binaries from our C++ files; use g++, include the cryptopp folder for the headers, and link the cryptopp library:
```bash
g++ rsa.cpp -o rsa.bin -I cryptopp/ -lcryptopp
```
- To compile README.md and other markdown files with a github aesthetic, first install grip
```bash
pip3 install grip
```
- then do:
```bash
grip README.md --export README.html
```
## How to use
- To generate keyfiles:
```bash
./rsa.bin -g name_of_owner
```
- To encrypt a message:
(name on keyfile should match name of recipient for convenience)
```bash
./rsa.bin -e "your message" -k name_on_public_keyfile -o ciphertext.dat
```
- To decrypt a message:
```bash
./rsa.bin -d ciphertext.dat -k name_on_private_keyfile
```
