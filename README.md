# Firmware for The Tablet Communication System
    The Tablet is a secure communication device designed according the NSAR (Non-Symmetric Accessibility Relation) security policy.


## How it works
    All data handling components are effectively air-gapped from upstream components to prevent information leakage to devices connected upstream. Asymmetric encryption masks every message sent, and decryption is handled in such a way as to guarantee plaintext is hardware inaccessible to any networked device.


## Installation

- Clone this repository.
- Clone Cryptopp into the root of this repository.
- Install Cryptopp by:

```
cd path/to/this/repository/
cd cryptopp/
make
sudo make install
```

### Optional
For contributors to the project do this before making your first commit:

- Install pre-commit

```
sudo apt install pre-commit
cd path/to/this/repository/
pre-commit install
```

## How to Compile

- use g++, include the cryptopp folder for headers, and link the cryptopp library.

```
g++ rsa.cpp -o rsa.bin -I cryptopp/ -lcryptopp
```

## How to use

```
```
