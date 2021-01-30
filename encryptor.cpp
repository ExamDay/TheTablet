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

SecByteBlock EncrApp (char *keyName, char* inputPlaintext, int ptBytes) {

    AutoSeededRandomPool asRP;

    RSA::PublicKey pubKey;

    pubKey.Initialize(int_n, int_e);

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

SecByteBlock DecrApp(SecByteBlock sBB, char* keyName) {

    AutoSeededRandomPool rng;

    RSA::PrivateKey pvK;



    RSAES<OAEP<SHA256> >::Decryptor decryptor(pvK);

    assert(0 != decryptor.FixedCiphertextLength());
    assert(sBB.size() <= decryptor.FixedCiphertextLength());

    size_t declength = decryptor.MaxPlaintextLength(sBB.size());
    assert (0 != declength);
    SecByteBlock recovered(declength);

    DecodingResult finout = decryptor.Decrypt(rng, sBB, sBB.size(), recovered);

    assert(finout.isValidCoding);
    assert(finout.messageLength <= decryptor.MaxPlaintextLength(sBB.size()));

    return recovered;
};

int main (int argc, char **argv)
{
  int aflag = 0;
  int bflag = 0;
  int dflag = 0;
  int eflag = 0;
  int gflag = 0;
  int kflag = 0;
  char *dvalue = NULL;
  char *evalue = NULL;
  char *gvalue = NULL;
  char *kvalue = NULL;
  int index;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, ":abd:e:g:k:")) != -1)
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

  // printf ("aflag = %d, bflag = %d, cvalue = %s\n",
  //         aflag, bflag, cvalue);


  //decryption code
  if (dflag == 1 && kflag == 1) {

    int dBytes = sizeof(dvalue);

    SecByteBlock sbb2(dBytes);

    for (int i = 0; i < dBytes; i++) {
        sbb2[i]= dvalue[i];
    }


    SecByteBlock ddr = DecrApp(sbb2, kvalue);

    cout << ddr.data() << endl;

  }

  if (eflag == 1 && kflag == 1) {

    int plainBytes = sizeof(evalue);

    SecByteBlock sbb3 = EncrApp(kvalue, evalue, plainBytes);

    cout << sbb3.data() << endl;

  }

  if (gflag == 1) {

    KeyGen(gvalue);

  }

  for (index = optind; index < argc; index++)
    printf ("Non-option argument %s\n", argv[index]);
  return 0;


}
