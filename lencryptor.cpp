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
#include <files.h>
#include <hex.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>
#include <sha512_armv4.h>

using namespace std;
using namespace CryptoPP;

int KeyGen(const string fName) {

  AutoSeededRandomPool asP;
  InvertibleRSAFunction inv;
  inv.GenerateRandomWithKeySize(asP, 2047);

  RSA::PrivateKey pvtKey(inv);
  RSA::PublicKey pubKey(inv);

  fstream keys;
  // keys.open(fName, ios::out);
  // save file containing RSA function
  // keys << "n\n";
  // keys << inv.GetModulus(); //n
  // keys << "\np\n";
  // keys << inv.GetPrime1(); //p
  // keys << "\nq\n";
  // keys << inv.GetPrime2(); //q
  // keys << "\nd\n";
  // keys << inv.GetPrivateExponent(); //d
  // keys << "\ne\n";
  // keys << inv.GetPublicExponent(); //e

  ByteQueue queue;
  pubKey.Save(queue);
  string pubName = "pub_" + fName;
  Save(pubName, queue);

  ByteQueue queue;
  privKey.Save(queue);
  string privName = "priv_" + fName;
  Save(privName, queue);

  // keys.close();

  return 0;
};

SecByteBlock GetKeyVal(char *fname, char header) {

  fstream keys;
  keys.open(fname, ios::in);
  string str;
  string st2;

  int len;

  while (std::getline(keys, str)) {
    if (str.length() < 3) {
      if (str.at(0) == header) {
        // cout << "\n";
        // cout << str;
        // cout << "\n";
        getline(keys, st2);
        // cout << st2 << endl;

        len = st2.length();
      }
    }
  }

  SecByteBlock sbb(reinterpret_cast<const byte *>(&st2[0]), st2.size());

  // cout << endl << sbb.data() << endl;

  keys.close();

  return sbb;
};

Integer GetIntKeyVal(char *fname, char header) {

  fstream keys;
  keys.open(fname, ios::in);
  string str;
  string st2;

  int len;

  while (std::getline(keys, str)) {
    if (str.length() < 3) {
      if (str.at(0) == header) {
        getline(keys, st2);
        len = st2.length();
      }
    }
  }

  keys.close();

  cout << endl << endl << st2 << endl << endl;

  Integer in = strtoull(st2);

  return in;
};

SecByteBlock EncrApp(char *keyName, char *inputPlaintext, int ptBytes) {

  AutoSeededRandomPool asRP;

  Integer int_n = GetKeyVal(keyName, 'n');
  Integer int_e = GetKeyVal(keyName, 'e');
  // Integer int_d = GetIntKeyVal(keyName, 'd');

  RSA::PublicKey pubKey;

  pubKey.Initialize(int_n, int_e);

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

  encryptor.Encrypt(asRP, plaintext, plaintext.size(), ciphertext);

  return ciphertext;
}

SecByteBlock DecrApp(SecByteBlock sBB, char *keyName) {

  AutoSeededRandomPool rng;

  RSA::PrivateKey pvK;

  Integer int_n = GetKeyVal(keyName, 'n');
  Integer int_e = GetKeyVal(keyName, 'e');
  Integer int_d = GetKeyVal(keyName, 'd');

  pvK.Initialize(int_n, int_e, int_d);

  RSAES<OAEP<SHA256>>::Decryptor decryptor(pvK);

  assert(0 != decryptor.FixedCiphertextLength());
  assert(sBB.size() <= decryptor.FixedCiphertextLength());

  size_t declength = decryptor.MaxPlaintextLength(sBB.size());
  assert(0 != declength);
  SecByteBlock recovered(declength);

  DecodingResult finout = decryptor.Decrypt(rng, sBB, sBB.size(), recovered);

  assert(finout.isValidCoding);
  assert(finout.messageLength <= decryptor.MaxPlaintextLength(sBB.size()));

  return recovered;
};

int main(int argc, char **argv) {
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

  while ((c = getopt(argc, argv, ":abd:e:g:k:")) != -1)
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

  // printf ("aflag = %d, bflag = %d, cvalue = %s\n",
  //         aflag, bflag, cvalue);

  // decryption code
  if (dflag == 1 && kflag == 1) {

    int dBytes = sizeof(dvalue);

    SecByteBlock sbb2(dBytes);

    for (int i = 0; i < dBytes; i++) {
      sbb2[i] = dvalue[i];
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
    printf("Non-option argument %s\n", argv[index]);
  return 0;
}
