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

// void SavePrivateKey(const string& filename, const PrivateKey& key);
// void SavePublicKey(const string& filename, const PublicKey& key);

void Load(string &filename, BufferedTransformation &bt) {
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

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

void keySave(string fileName, RSA::PublicKey key){
    // saves public/private key-pairs to disk in ".key" files.
    ByteQueue queue;
    key.Save(queue);
    fileName = fileName + ".key";
    FileSink file(fileName.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
};

void keySave(string fileName, RSA::PrivateKey key) {
    // saves public/private key-pairs to disk in ".key" files.
    ByteQueue queue;
    key.Save(queue);
    fileName = fileName + ".key";
    FileSink file(fileName.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
};

int KeyGen(string fName) {

    AutoSeededRandomPool rng;
    InvertibleRSAFunction inv;
    inv.GenerateRandomWithKeySize(rng, 2048);

    RSA::PrivateKey privKey(inv);
    RSA::PublicKey pubKey(inv);

    // ByteQueue queue;
    // pubKey.Save(queue);
    string pubName = "public_" + fName;
    keySave(pubName, pubKey);

    // queue.Clear();
    // privKey.Save(queue);
    string privName = "private_" + fName;
    keySave(privName, privKey);

    return 0;
};

SecByteBlock EncrApp(string keyName, char *inputPlaintext, int ptBytes) {

    AutoSeededRandomPool rng;

    RSA::PublicKey pubKey;

    string pubKeyName = "public_" + keyName + ".key";

    LoadPublicKey(pubKeyName, pubKey);

    SecByteBlock plaintext(ptBytes);

    for (int i = 0; i < ptBytes; i++) {
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

SecByteBlock DecrApp(string fileName, string keyName) {

    AutoSeededRandomPool rng;
    string keyFname = "private_" + keyName + ".key";
    RSA::PrivateKey privKey;
    LoadPrivateKey(keyFname, privKey);

    basic_ifstream<byte> file;

    file.open(fileName);
    file.seekg(0, file.end);
    int fileLength = file.tellg();
    file.seekg(0, file.beg);
    file.close();

    SecByteBlock ciphertext(fileLength);
    // file.read(&ciphertext[0], fileLength);
    // file.close();

    ByteQueue buffer;
    Load(fileName, buffer);

    cout << "BUFFER CONTENTS\n\n";
    byte *dataptr = ciphertext.data();
    for (int i = 0; i < fileLength; i++) {
        cout << buffer[i];
        memset(dataptr, buffer[i], 1);
        dataptr++;
    };
    buffer.Clear();
    cout << "\n\nWEED\n";

    RSAES<OAEP<SHA256>>::Decryptor decryptor(privKey);

    // Now that there is a concrete object, we can check sizes
    assert(0 != decryptor.FixedCiphertextLength());
    assert(ciphertext.size() <= decryptor.FixedCiphertextLength());

    cout << "ciphertext size in bytes: " << ciphertext.size() << endl;
    size_t declength = decryptor.MaxPlaintextLength(ciphertext.size());
    // assert (0 != declength);
    SecByteBlock recovered(declength);

    DecodingResult result =
        decryptor.Decrypt(rng, ciphertext, ciphertext.size(), recovered);

    assert(result.isValidCoding);
    assert(result.messageLength <=
           decryptor.MaxPlaintextLength(ciphertext.size()));

    recovered.resize(result.messageLength);

    // cout << "\n\nTEST\n" << endl;
    // const unsigned char *byte = recovered;
    // int size =result.messageLength;
    // while (size > 0) {
    //     size--;
    //     printf("%c ", *byte);
    //     byte++;
    // }
    // cout << "\n\nEND TEST\n" << endl;

    cout << "\n\nrecovered:\n" << recovered.data() << endl;
    return recovered;
};

// SecByteBlock dec(SecByteBlock ciphertext, int size, string keyName) {

//     cout << "\nciphertext: " << ciphertext.data() << endl;
//     cout << "\nsize: " << size << endl;

//     AutoSeededRandomPool rng;

//     string kname = "private_" + keyName + ".key";

//     RSA::PrivateKey privKey;
//     LoadPrivateKey(kname, privKey);

//     RSAES<OAEP<SHA256>>::Decryptor decryptor(privKey);

//     size_t declength = decryptor.MaxPlaintextLength(size);
//     cout << "\ndeclength: " << declength << endl;
//     SecByteBlock recovered(declength);

//     DecodingResult finout =
//         decryptor.Decrypt(rng, ciphertext, size, recovered);
//     cout << "finout valid?: " << finout.isValidCoding << endl;
//     cout << "finout length:" << finout.messageLength << endl;

//     cout << "\n\nTEST\n" << endl;
//     unsigned char *item = &recovered[0];
//     size = finout.messageLength;
//     while (size > 0) {
//         size--;
//         printf("%c ", *item);
//         item++;
//     }
//     cout << "\n\nEND TEST\n" << endl;
//     // cout << "finout: " << finout.data() << endl;
//     return recovered;
// };

int main(int argc, char **argv) {
    int aflag = 0;
    int bflag = 0;
    int dflag = 0;
    int eflag = 0;
    int gflag = 0;
    int fflag = 0;
    int kflag = 0;
    char *dvalue = NULL;
    char *evalue = NULL;
    char *fvalue = NULL;
    char *gvalue = NULL;
    char *kvalue = NULL;
    int index;
    int c;

    opterr = 0;

    while ((c = getopt(argc, argv, ":abd:e:f:g:k:")) != -1)
        switch (c) {
        case 'a':
            aflag = 1;
            break;
        case 'b':
            bflag = 1;
            break;
        case 'd':
            dvalue = optarg;
            dflag = 1;
        case 'e':
            evalue = optarg;
            eflag = 1;
            break;
        case 'f':
            fvalue = optarg;
            fflag = 1;
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
            if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            return 1;
        default:
            abort();
        }

    // decryption code
    if (dflag == 1 && kflag == 1) {

        string ciphertextFileName(dvalue);
        cout << ciphertextFileName << endl;
        SecByteBlock recovered = DecrApp(dvalue, kvalue);
        cout << "\n\nrecovered:\n" << recovered.data() << endl;

    }

    else if (eflag == 1 && kflag == 1 && fflag == 1) {

        int plainBytes = sizeof(evalue);
        SecByteBlock encodedMessage = EncrApp(kvalue, evalue, plainBytes);
        cout << encodedMessage.data() << endl;
        fstream encRes;
        string encFname = fvalue;
        encFname = encFname + ".dat";
        cout << encFname << endl;
        encRes.open(encFname, ios::out);
        encRes.write((const char *)encodedMessage.data(),
                     encodedMessage.size());
        // encRes << encodedMessage << endl;
        encRes.close();

        // TEST
        basic_ifstream<byte> file;

        file.open(encFname);
        file.seekg(0, file.end);
        int fileLength = file.tellg();
        file.seekg(0, file.beg);
        file.close();

        SecByteBlock ciphertext(fileLength);

        ByteQueue buffer;
        Load(encFname, buffer);

        cout << "FILE CONTENTS\n\n";
        byte *dataptr = ciphertext.data();
        for (int i = 0; i < fileLength; i++) {
            cout << buffer[i];
            memset(dataptr, buffer[i], 1);
            dataptr++;
        };
        buffer.Clear();

        cout << "\n\nWEED\n";

        assert(encodedMessage == ciphertext);
        assert(*encodedMessage.data() == *ciphertext.data());
        // END TEST

    }

    else if (gflag == 1) {

        KeyGen(gvalue);

    }

    else {
        cout << "Invalid use of program. Terminating." << endl;
        for (index = optind; index < argc; index++) {
            printf("Non-option argument %s\n", argv[index]);
        };
        abort();
    }

    return 0;
}
