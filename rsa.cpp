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

void keySave(string fileName, RSA::PublicKey key) {
    // saves public keys to disk into a ".key" file.
    ByteQueue queue;
    key.Save(queue);
    fileName = fileName + ".key";
    FileSink file(fileName.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
};

void keySave(string fileName, RSA::PrivateKey key) {
    // saves private keys to disk into a ".key" file.
    ByteQueue queue;
    key.Save(queue);
    fileName = fileName + ".key";
    FileSink file(fileName.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
};

int keyFileGen(string fileName, size_t keySize) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction inv;
    inv.GenerateRandomWithKeySize(rng, keySize);

    RSA::PrivateKey privKey(inv);
    RSA::PublicKey pubKey(inv);

    string pubName = "public_" + fileName;
    keySave(pubName, pubKey);

    string privName = "private_" + fileName;
    keySave(privName, privKey);

    return 0;
};

void LoadPublicKey(string &filename, PublicKey &key) {
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}

void LoadPrivateKey(string &filename, PrivateKey &key) {
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}

SecByteBlock charToSecBlock(char *text, size_t textLength) {
    // copies data from an array of chars into the data region of a SecByteBlock
    SecByteBlock secbb(textLength);
    byte *secPtr = secbb.data();
    for (int i = 0; i < textLength; i++) {
        memset(secPtr, text[i], 1);
        secPtr++;
    };
    return secbb;
};

void saveSecBytes(string filename, SecByteBlock secBlock) {
    fstream file;
    cout << filename << endl;
    file.open(filename, ios::out);
    file.write((const char *)secBlock.data(), secBlock.size());
    file.close();
};

SecByteBlock loadSecBytes(string filename) {
    // loads the bytes of a file (probably containing an RSA encrypted message)
    // into a SecByteBlock and returns that block.
    basic_ifstream<byte> file;

    file.open(filename);
    file.seekg(0, file.end);
    int fileLength = file.tellg();
    file.seekg(0, file.beg);
    file.close();

    SecByteBlock ciphertext(fileLength);

    ByteQueue buffer;
    Load(filename, buffer);

    // cout << "\n\nfile length: " << fileLength << endl;
    byte *dataptr = ciphertext.data();
    for (int i = 0; i < fileLength; i++) {
        // cout << buffer[i];
        memset(dataptr, buffer[i], 1);
        dataptr++;
    };
    buffer.Clear();
    return ciphertext;
};

SecByteBlock Encrypt(string keyName, char *inputPlaintext, int plaintextLength) {

    AutoSeededRandomPool rng;
    RSA::PublicKey pubKey;
    string pubKeyName = "public_" + keyName + ".key";
    LoadPublicKey(pubKeyName, pubKey);

    SecByteBlock plaintext(plaintextLength);

    for (int i = 0; i < plaintextLength; i++) {
        plaintext[i] = inputPlaintext[i];
    }

    RSAES<OAEP<SHA256>>::Encryptor encryptor(pubKey);

    assert(0 != encryptor.FixedMaxPlaintextLength());
    assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

    size_t enclength = encryptor.CiphertextLength(plaintext.size());
    assert(0 != enclength);

    SecByteBlock ciphertext(enclength);

    encryptor.Encrypt(rng, plaintext, plaintext.size(), ciphertext);

    return ciphertext;
}

SecByteBlock Decrypt(SecByteBlock ciphertext, RSA::PrivateKey privKey) {
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Decryptor decryptor(privKey);

    // Check sizes
    assert(0 != decryptor.FixedCiphertextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    // Create recovered text space
    size_t maxLength = decryptor.MaxPlaintextLength(ciphertext.size());
    assert(0 != maxLength);
    SecByteBlock recovered(maxLength);
    DecodingResult decodeReport = decryptor.Decrypt(rng, ciphertext, ciphertext.size(), recovered);

    // More sanity checks
    assert(decodeReport.isValidCoding);
    assert(decodeReport.messageLength <= decryptor.MaxPlaintextLength(ciphertext.size()));

    recovered.resize(decodeReport.messageLength);

    // cout << "\n\nmessage length: " << decodeReport.messageLength << endl;

    // cout << "\n\nrecovered size:\n" << recovered.size() << endl;
    return recovered;
};

int main(int argc, char **argv) {
    int aflag = 0;
    int bflag = 0;
    int dflag = 0;
    int eflag = 0;
    int gflag = 0;
    int oflag = 0;
    int kflag = 0;
    char *dvalue = NULL;
    char *evalue = NULL;
    char *ovalue = NULL;
    char *gvalue = NULL;
    char *kvalue = NULL;
    int index;
    int c;

    opterr = 0;

    while ((c = getopt(argc, argv, ":d:e:o:g:k:")) != -1)
        switch (c) {
        case 'd':
            dvalue = optarg;
            dflag = 1;
        case 'e':
            evalue = optarg;
            eflag = 1;
            break;
        case 'o':
            ovalue = optarg;
            oflag = 1;
            break;
        case 'g':
            gvalue = optarg;
            gflag = 1;
            break;
        case 'k':
            kvalue = optarg;
            kflag = 1;
            break;
        case '?':
            if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);

            return 1;

        default:
            abort();
        };

    if (dflag == 1 && kflag == 1) {
        SecByteBlock ciphertext = loadSecBytes(dvalue);
        RSA::PrivateKey privKey;
        string privKeyName = "private_" + (string)kvalue + ".key";
        LoadPrivateKey(privKeyName, privKey);
        SecByteBlock recovered = Decrypt(ciphertext, privKey);
        // cout << "recovered:\n" << recovered.data() << endl;

        cout << "Recovered plaintext:" << endl;

        for (int ch = 0; ch < recovered.size(); ch ++) {
           cout << recovered[ch];
        }

        cout << endl;

    }
    else if (eflag == 1 && kflag == 1 && oflag == 1) {
        int plainLength = strlen(evalue);
        SecByteBlock ciphertext = Encrypt(kvalue, evalue, plainLength);
        // cout << "\n\nencodedMessage:\n" << ciphertext.data() << endl;
        // Save
        saveSecBytes(ovalue, ciphertext);
    }
    else if (gflag == 1) {
        keyFileGen(gvalue, 2048);
    }
    else {
        cout << "Invalid use of program. Terminating." << endl;
        for (index = optind; index < argc; index++) {
            printf("Non-option argument %s\n", argv[index]);
        };

        return 1;

    }

    return 0;
};
