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

void keySave(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

int keyGen(const string fName) {

  AutoSeededRandomPool asP;
  InvertibleRSAFunction inv;
  inv.GenerateRandomWithKeySize(asP, 2047);

  RSA::PrivateKey privKey(inv);
  RSA::PublicKey pubKey(inv);

  ByteQueue queue;
  pubKey.Save(queue);
  string pubName = "pub_" + fName;
  keySave(pubName, queue);

  queue.Clear();
  privKey.Save(queue);
  string privName = "priv_" + fName;
  Save(privName, queue);

  // keys.close();

  return 0;
};

int main(){
    keyGen("key.stash");
};
