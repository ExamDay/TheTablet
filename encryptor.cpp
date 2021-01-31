// standard headers:
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <typeinfo>
#include <math.h>
#include <chrono>
#include <stdarg.h>
#include <cassert>
#include <stdio.h>
#include <unistd.h>
// cryptopp headers:
#include <cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
#include <sha.h>
#include <hex.h>
#include <files.h>
#include <sha512_armv4.h>
#include <rsa.h>
#include <osrng.h>

using namespace std;
using namespace CryptoPP;

// void SavePrivateKey(const string& filename, const PrivateKey& key);
// void SavePublicKey(const string& filename, const PublicKey& key);

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);
}

void keySave(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

int KeyGen(const string fName) {

  AutoSeededRandomPool asP;
  InvertibleRSAFunction inv;
  inv.GenerateRandomWithKeySize(asP, 2047);

  RSA::PrivateKey privKey(inv);
  RSA::PublicKey pubKey(inv);

  ByteQueue queue;
  pubKey.Save(queue);
  string pubName = "public_" + fName;
  keySave(pubName, queue);

  queue.Clear();
  privKey.Save(queue);
  string privName = "private_" + fName;
  keySave(privName, queue);

  return 0;

};

SecByteBlock EncrApp (string keyName, char* inputPlaintext, int ptBytes) {

    AutoSeededRandomPool asRP;

    RSA::PublicKey pubKey;

    string pubKeyName = "public_" + keyName;

    LoadPublicKey(pubKeyName, pubKey);

    SecByteBlock plaintext(ptBytes);

    for (int i = 0; i < ptBytes; i++) {
        plaintext[i]= inputPlaintext[i];
    }

    RSAES<OAEP<SHA256> >::Encryptor encryptor(pubKey);

    assert(0 != encryptor.FixedMaxPlaintextLength());
    assert(plaintext.size() <= encryptor.FixedMaxPlaintextLength());

    size_t enclength = encryptor.CiphertextLength(plaintext.size());
    assert(0 != enclength);

    SecByteBlock ciphertext(enclength);

    encryptor.Encrypt(asRP, plaintext, plaintext.size(), ciphertext);

    return ciphertext;

}

SecByteBlock DecrApp(string cFileName, string keyName) {

    AutoSeededRandomPool rng;

    RSA::PrivateKey privKey;

    string kname = "private_" + keyName;

    LoadPrivateKey(kname, privKey);

    string cname = cFileName + ".dat";

    basic_ifstream<unsigned char> cFile;

    cFile.open(cname);

    cFile.seekg(0, cFile.end);
    int fileLength = cFile.tellg();
    cFile.seekg(0, cFile.beg);

    unsigned char* buffer = new unsigned char [fileLength - 1];

    cFile.read(buffer, fileLength - 1);

    SecByteBlock sBB(fileLength - 1);

    for(int i = 0; i < fileLength - 1; i++) { //whacking EOF character

      sBB[i] = buffer[i];

    }

    cout << "BUFFER CONTENTS\n\n" << buffer << "\n\nNIGGA\n";

    RSAES<OAEP<SHA256> >::Decryptor decryptor(privKey);

    // assert(0 != decryptor.FixedCiphertextLength());
    // assert(sBB.size() <= decryptor.FixedCiphertextLength());

    size_t declength = decryptor.MaxPlaintextLength(sBB.size());
    // assert (0 != declength);
    SecByteBlock recovered(declength);

    DecodingResult finout = decryptor.Decrypt(rng, sBB, sBB.size(), recovered);

    // assert(finout.isValidCoding);
    // assert(finout.messageLength <= decryptor.MaxPlaintextLength(sBB.size()));

    return recovered;
};

int main (int argc, char **argv)
{
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

  while ((c = getopt (argc, argv, ":abd:e:f:g:k:")) != -1)
    switch (c)
      {
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
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();
      }

  //decryption code
  if (dflag == 1 && kflag == 1) {

    string ciphertextFileName(dvalue);

    SecByteBlock decodeResult = DecrApp(dvalue, kvalue);

    cout << decodeResult.data() << endl;

  }

  else if (eflag == 1 && kflag == 1 && fflag == 1) {

    int plainBytes = sizeof(evalue);

    SecByteBlock encodedMessage = EncrApp(kvalue, evalue, plainBytes);

    cout << encodedMessage.data() << endl;

    fstream decres;

    string decrFname(fvalue);

    string decrFnameInPractice = decrFname + ".dat";
    decres.open(decrFnameInPractice, ios::out);

    decres << encodedMessage.data() << endl;

    decres.close();

  }

  else if (gflag == 1) {

    KeyGen(gvalue);

  }

  else {
    cout << "Invalid use of program. Terminating." << endl;
    abort ();
  }

  for (index = optind; index < argc; index++)
    printf ("Non-option argument %s\n", argv[index]);
  return 0;


}
