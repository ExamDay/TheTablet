// standard headers:
#include <cassert>
#include <chrono>
#include <fstream>
#include <iostream>
#include <math.h>
#include <sstream>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <typeinfo>
#include <unistd.h>
// cryptopp headers:
#include <cryptlib.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
#include <files.h>
#include <hex.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>
#include <sha512_armv4.h>

using namespace std;
using namespace CryptoPP;

void Load(string &filename, BufferedTransformation &bt) {
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

int main() {
    // Generate keys
    AutoSeededRandomPool rng;

    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 2048);

    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);

    ////////////////////////////////////////////////
    // Secret to protect
    // static const int SECRET_SIZE = 160;
    char secret[] = "DANK WEED FUCK YEAH SU GOIIIII!";
    SecByteBlock plaintext(strlen(secret));
    // memset(plaintext, 'A', SECRET_SIZE);
    byte *plainptr = plaintext.data(); 
    for (int i = 0; i < strlen(secret); i++) {
        memset(plainptr, secret[i], 1);
        plainptr++;
    };

    ////////////////////////////////////////////////
    // Encrypt
    RSAES<OAEP<SHA256>>::Encryptor encryptor(publicKey);

    // Now that there is a concrete object, we can validate
    assert(0 != encryptor.FixedMaxPlaintextLength());
    assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

    // Create cipher text space
    size_t ecl = encryptor.CiphertextLength(plaintext.size());
    assert(0 != ecl);
    SecByteBlock encodedMessage(ecl);

    encryptor.Encrypt(rng, plaintext, plaintext.size(), encodedMessage);

    cout << "\n\nencodedMessage:\n" << encodedMessage.data() << endl;

    ////////////////////////////////////////////////
    // Save and Retrieve
    // Save
    fstream encRes;
    string encFname = "testenc.dat";
    cout << encFname << endl;
    encRes.open(encFname, ios::out);
    encRes.write((const char *)encodedMessage.data(), encodedMessage.size());
    // encRes << encodedMessage << endl;
    encRes.close();

    // Retrieve
    basic_ifstream<byte> file;

    file.open(encFname);
    file.seekg(0, file.end);
    int fileLength = file.tellg();
    file.seekg(0, file.beg);
    file.close();

    SecByteBlock ciphertext(fileLength);

    ByteQueue buffer;
    Load(encFname, buffer);
    
    cout << "\n\nfile length: " << fileLength << endl;
    byte *dataptr = ciphertext.data();
    for (int i = 0; i < fileLength; i++) {
        cout << buffer[i];
        memset(dataptr, buffer[i], 1);
        dataptr++;
    };
    buffer.Clear();

    assert(encodedMessage == ciphertext);
    assert(*encodedMessage.data() == *ciphertext.data());

    ////////////////////////////////////////////////
    // Decrypt
    RSAES<OAEP<SHA256>>::Decryptor decryptor(privateKey);

    // Now that there is a concrete object, we can check sizes
    assert(0 != decryptor.FixedCiphertextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength(ciphertext.size());
    assert(0 != dpl);
    SecByteBlock recovered(dpl);
    DecodingResult result =
        decryptor.Decrypt(rng, ciphertext, ciphertext.size(), recovered);

    // More sanity checks
    assert(result.isValidCoding);
    assert(result.messageLength <=
           decryptor.MaxPlaintextLength(ciphertext.size()));

    // At this point, we can set the size of the recovered
    //  data. Until decryption occurs (successfully), we
    //  only know its maximum size
    recovered.resize(result.messageLength);

    // SecByteBlock is overloaded for proper results below
    assert(plaintext == recovered);

    cout << "\n\nrecovered size:\n" << recovered.size() << endl;
    cout << "\n\nrecovered:\n"; 
    byte *recoveredptr = recovered.data();
    for (int i = 0; i < recovered.size(); i++) {
        cout << *recoveredptr; 
        recoveredptr++;
    };
    cout << endl;

    return 1;
};
