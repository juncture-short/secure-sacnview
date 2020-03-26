// Copyright 2020 Scott McKay
// http://www.pathwayconnectivity.com
//
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


#ifndef SACNSECURITYTOOLS_H
#define SACNSECURITYTOOLS_H

#include <string>
#include <QByteArray>

class sACNSecurityTools
{
public:
	static const int KeyFingerprintSize = 4;
	static const int passwordSize = 32;
	static const int MessageDigestSize = 16;

	sACNSecurityTools();

	static std::string getKeyFingerprint(std::string key);
	static QByteArray messageDigest(QByteArray message, QString password, quint8 sequenceType, quint64 sequenceNumber);

	static bool verifyPacket(QByteArray packet, QString password);
};

#endif // SACNSECURITYTOOLS_H
