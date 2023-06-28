#include <Crypto.h>
#include <SHA256.h>
#include <AES.h>
#include <string.h>
#include <EEPROM.h>
#include "UUID.h"

#define HASH_SIZE 32
#define BLOCK_SIZE 64


const char* AES_KEY = "OHAuthDefaultAES";
const char* XOR_KEY = "OHAuthDefaultXOR";

AES256 aes256;

UUID uuid;
char* ID;

// EEPROM BEGIN
void writeStringToEEPROM(int addrOffset, const char *strToWrite)
{
  byte len = strlen(strToWrite);
  EEPROM.write(addrOffset, len);

  for (int i = 0; i < len; i++)
  {
    EEPROM.write(addrOffset + 1 + i, strToWrite[i]);
  }
}

char* readStringFromEEPROM(int addrOffset)
{
  int newStrLen = EEPROM.read(addrOffset);
  char data[newStrLen + 1];

  for (int i = 0; i < newStrLen; i++)
  {
    data[i] = EEPROM.read(addrOffset + 1 + i);
  }
  data[newStrLen] = '\0';
  return data;
}
// EEPROM END

void transformChallenge(byte* challenge, size_t length) {
  for (size_t i = 0; i < length; i++) {
    challenge[i] ^= XOR_KEY[i % sizeof(XOR_KEY)];
  }
}

void setup() {
  Serial.begin(115200);

  delay(3000);
  ID = readStringFromEEPROM(0);
  if ((int)ID[0] == -1)
  {
    randomSeed(analogRead(A0));
    uint32_t seed1 = random(256);
    randomSeed(analogRead(A0));
    uint32_t seed2 = random(255);

    uuid.seed(seed1, seed2);
    uuid.generate();
    ID = uuid.toCharArray();
    writeStringToEEPROM(0, ID);
  }
}

void loop() {
  char buffer[1024];
  if (Serial.available() > 0)
  {
    String data = Serial.readString();
    aes256.setKey(AES_KEY, aes256.keySize());
    aes256.decryptBlock(buffer, data.c_str());
    
    transformChallenge(buffer, strlen(buffer));
  }
}