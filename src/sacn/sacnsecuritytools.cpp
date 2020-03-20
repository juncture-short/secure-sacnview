// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "sacnsecuritytools.h"

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>

#include <cryptopp/blake2.h>

sACNSecurityTools::sACNSecurityTools()
{

}

//-----------------------------------------------------------------------------
std::string sACNSecurityTools::getKeyFingerprint(std::string key) {
	std::string digest;
	CryptoPP::BLAKE2s hash;
	hash.Update((const CryptoPP::byte*)key.data(), key.size());
	digest.resize(KeyFingerprintSize);
	hash.TruncatedFinal((CryptoPP::byte*)&digest[0], KeyFingerprintSize);

	return digest;
}

//-----------------------------------------------------------------------------
QByteArray sACNSecurityTools::messageDigest(QByteArray message, std::string pass, quint8 sequenceType, quint64 sequenceNumber) {
	quint64 sequenceNumberMask = (1l << (7*8)) - 1; //We only want the first 7 bytes if the 8 Byte value
	sequenceNumber &= sequenceNumberMask;
	quint64 sequence = (static_cast<quint64>(sequenceType) << (7*8)) + sequenceNumber;

	std::string key = getKeyFingerprint(pass);

	QDataStream stream(&message, QIODevice::ReadWrite);
	stream.skipRawData(message.size());
	stream.writeRawData(key.c_str(), key.length());
	stream << sequence;

	std::string digest;
	CryptoPP::BLAKE2s hash((const CryptoPP::byte*) key.data(), key.size());
	hash.Update((const CryptoPP::byte*)message.data(), message.size());
	digest.resize(MessageDigestSize);
	hash.TruncatedFinal((CryptoPP::byte*)&digest[0], MessageDigestSize);

	stream.writeRawData(digest.c_str(), digest.size());

	return message;
}
