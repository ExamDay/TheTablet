<p align="center">Firmware for</p>
<h1 align="center">The Tablet:<br>A Secure Communication System</h1>

The Tablet is a secure communication device designed to implement the NSAR (Non-Symmetric Accessibility Relation) security policy.
## How it works
All data handling components are air-gapped from upstream components to prevent information leakage to any connected device. Asymmetric encryption masks every message sent, and decryption is handled in such a way as to guarantee plaintext is hardware inaccessible to any networked device.
## Installing Dependencies
- Clone this repository.
```bash
git clone git@git.blackboxlabs.dev:/srv/git/tablet.git
```
- Clone Cryptopp into the root of this repository.
```bash
cd tablet
git clone https://github.com/weidai11/cryptopp.git
```
- Install Cryptopp by:
```bash
cd cryptopp/
make
sudo make install
```
## How to Compile
- To compile binaries from our C++ files; use g++, include the cryptopp folder for the headers, and link the cryptopp library like so:
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
## Contributing
For contributors to the project; do this before making your first commit:

- Install pre-commit
```bash
cd /path/to/this/repository/
sudo apt install pre-commit
pre-commit install
```
(we do all of our development on linux)

- To test updates to the readme and other GitHub flavored markdown, simply install Grip
and feed it your desired file.
```bash
pip3 install grip
grip README.md
```
- Then follow the link provided by the Grip sever for a live preview of your work.

- When satisfied with your changes you can compile to an html file with:
```bash
grip README.md --export README.html
```
## Authors
* **Gabe M. LaFond** - *Initial work* - [ExamDay](https://github.com/ExamDay)

See also the list of [contributors](https://github.com/ExamDay/TheTablet/contributors) who participated in this project.
## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
