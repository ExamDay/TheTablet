// standard headers:
#include <iostream>
#include <string>
#include <sstream>
#include <typeinfo>
#include <math.h>
#include <chrono>
#include <stdarg.h>
// cryptopp headers:
#include <cryptlib.h>
#include <sha.h>
#include <hex.h>
#include <files.h>
#include <sha512_armv4.h>

using namespace std;

string Hash_CryptoPP(const string& msg)
{
	CryptoPP::SHA512 hash;
	string digest(hash.DigestSize(), '*');
	stringstream output;

	hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
	hash.Final((CryptoPP::byte*)&digest[0]);

	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(output));
	CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));

	return output.str();
}

int main () {
    string plainText = "Double our forces on every front over the next month.";
    cout << "plainText: " << plainText << endl;
    cout << "length of plainText: " << plainText.length() << endl;
    string message = plainText;
    for (int c = 0; c < plainText.length(); c++) {
        message[c]++;
    };
    cout << "message: " << message << endl;
    cout << "length of message: " << message.length() << endl;

	string msg = "Triple our forces on every front over the next year as well.";
	cout << "Message: " << msg << endl;
	cout << "Digest : " << Hash_CryptoPP(msg) << endl << endl;

    return 0;
};
