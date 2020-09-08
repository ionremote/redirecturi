
var PIN_BLOCK_FILL_CHARACTER = 0xFF;
var FMT_2_CONTROL_BYTE = 0x02;
var FMT_12_CONTROL_BYTE = 0xC1;
var ISO_FORMAT_2_TYPE = 1;
var ISO_FORMAT_12_TYPE = 2;
var MAX_PIN_STRING_SIZE = 30;
var MIN_PIN_STRING_SIZE = 4;
var MAX_NUMERIC_PIN_STRING_SIZE = 12;
var MAX_NUMERIC_PIN_BYTE_SIZE = 6;
var DECIMAL_RADIX = 10;
var NUM_OF_BYTES_IN_FMT2_PIN_BLOCK = 8;
var NUM_OF_BYTES_PER_CNTRL_AND_PIN_LENGTH = 2;
var ENCODING_PARAMETER_SIZE_IN_BYTES = 16;
var RANDOM_SEED_SIZE_IN_BYTES = 20;

var RSA_MODULUS_SIZE_IN_BITS = 0;
var RSA_MODULUS_SIZE_IN_BYTES = 0;
var RSA_EXPONENT_SIZE_IN_BYTES = 0;
var ONE_PIN_BLOCK_IN_MESSAGE = 1;
var SHA1_HASH_SIZE_IN_BYTES = 20;
var OAEP_SHA1_OFFSET_IN_BYTES = 42;
var MIN_PIN_MESSAGE_SIZE_IN_BYTES = 17;	
var MIN_PIN_BLOCK_SIZE = 8;
var MAX_MESSAGE_SIZE_IN_BYTES = 0;
var MIN_RANDOM_NUMBER_STRING_LENGTH = MIN_PIN_BLOCK_SIZE * NUM_OF_NIBBLES_PER_BYTE;
var ENCODED_MESSAGE_SIZE_IN_BYTES = 0;
var DATA_BLOCK_SIZE_IN_BYTES = 0;
var MAX_PIN_MESSAGE_SIZE_IN_BYTES = 0;

var ERR_INVALID_PIN_LENGTH = 10;			
var ERR_INVALID_PIN = 11;					
var ERR_INVALID_PIN_BLOCK = 20;				
var ERR_INVALID_RANDOM_NUMBER_LENGTH = 21;	
var ERR_INVALID_RANDOM_NUMBER = 22;			
var ERR_INVALID_PIN_MESSAGE = 30;			
var ERR_INVALID_PIN_MESSAGE_LENGTH = 31;	
var ERR_INVALID_ENCODED_MSG_LENGTH = 40;	
var ERR_INVALID_RSA_KEY_LENGTH = 41;		
var ERR_INVALID_RSA_KEY = 42;				


var publicExponentString = '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001';
var modulusString = '8423BC1DF851F46180C1476FD4B503D9457F7B2DCDB2DDBB5B9946803FFE5E2A8A9F5F5206AB723EC6A6082F445238808360FFFB9D5E651FD3C72FE5D3E6EDEEA5508711C8B173BE79EF24B9B43E8D84871B8267B7343DD3FAA0B49638E5B437EF51847974C7836261F1E0E1FDD9742CED624826F2DE1AE7A3CA6F0C5017326B';
var modulus;
var publicExponent;
var chunkSize;


var P = new Array(ENCODING_PARAMETER_SIZE_IN_BYTES);
var maxOutputDataSizeInBytes;

function PINBlock(PINBlockByteArray)
{
	this.length = PINBlockByteArray.length;
	this.byteArray = PINBlockByteArray;
}

function createPINBlock(pinString, RN_String)
{
  	var index;
	//20141208 - JJ - AppVA CR - start
	RSA_MODULUS_SIZE_IN_BITS = modulusString.length * 4;
	RSA_MODULUS_SIZE_IN_BYTES = parseInt(RSA_MODULUS_SIZE_IN_BITS / 8);
	RSA_EXPONENT_SIZE_IN_BYTES = parseInt(RSA_MODULUS_SIZE_IN_BITS / 8);
	MAX_MESSAGE_SIZE_IN_BYTES = RSA_MODULUS_SIZE_IN_BYTES - OAEP_SHA1_OFFSET_IN_BYTES;
	ENCODED_MESSAGE_SIZE_IN_BYTES = RSA_MODULUS_SIZE_IN_BYTES - 1;
	DATA_BLOCK_SIZE_IN_BYTES = ENCODED_MESSAGE_SIZE_IN_BYTES - SHA1_HASH_SIZE_IN_BYTES;
	MAX_PIN_MESSAGE_SIZE_IN_BYTES = RSA_MODULUS_SIZE_IN_BYTES - OAEP_SHA1_OFFSET_IN_BYTES;
	//20141208 - JJ - AppVA CR - end
	var PinStringByteArray = new Array(MAX_PIN_STRING_SIZE);
	var numericPinStringByteArray = new Array(MAX_NUMERIC_PIN_STRING_SIZE);
  	var pinChar;
	var pinCharCd;
  	var isInvalidCharFound = false;
  	var isPINNumeric = false;

	if (pinString == '') {
  	  return ERR_INVALID_PIN;
	}
	
  	PINLength = pinString.length;
  	if (PINLength > MAX_PIN_STRING_SIZE || PINLength < MIN_PIN_STRING_SIZE) {
  	  return ERR_INVALID_PIN_LENGTH;
  	}

 	if (PINLength <= MAX_NUMERIC_PIN_STRING_SIZE) {
  	  isPINNumeric = true;
 	}

  	for (index = 0; index < PINLength; index++)
  	{
  	  pinChar = pinString.charAt(index);
	  pinCharCd = pinString.charCodeAt(index);
 	  if (isPINNumeric) {
 	    if (isNaN(pinChar)) {
  	      isPINNumeric = false;
 	    } else {
 	      numericPinStringByteArray[index] = parseInt(pinChar, DECIMAL_RADIX);
 	    }
 	  }
 	  PinStringByteArray[index] = pinCharCd;
  	}

	if (isPINNumeric) {
	  createFormat2PINBlock(numericPinStringByteArray, PINLength, RN_String);
	} else {
	  createFormat12PINBlock(PinStringByteArray, PINLength, RN_String);
    }

	return 0;
}

function createFormat2PINBlock(numericPinByteArray, PINLength, RN_String)
{
  	var tempInt;

  	PINBlockType = ISO_FORMAT_2_TYPE;
  	PINBlockLength = NUM_OF_BYTES_IN_FMT2_PIN_BLOCK;
  	PINBlockByteArray = new Array(NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
	PINBlockByteArray = fillByteArray(PINBlockByteArray, PIN_BLOCK_FILL_CHARACTER);
  	tempInt = FMT_2_CONTROL_BYTE << 4;
	PINBlockByteArray[0] = (tempInt | (PINLength & 0x00FF));
 	PINBlockByteArray = convertAsciiArrayToHexByteArray(numericPinByteArray, PINBlockByteArray, 1, PINLength);
	createPINMessage(PINBlockByteArray, RN_String)
  	return;
}

function createFormat12PINBlock(PinStringByteArray, PINLength, RN_String)
{
    var numberOfPINBlocks;
	
  	PINBlockType = ISO_FORMAT_12_TYPE;
  	if (PINLength <= 6) {
  	  numberOfPINBlocks = 1;
  	} else {
  	  numberOfPINBlocks = 2 + parseInt((PINLength - 7) / NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
  	}
  	PINBlockLength = numberOfPINBlocks * NUM_OF_BYTES_IN_FMT2_PIN_BLOCK;

  	switch (numberOfPINBlocks)
  	{
  	  case 1:
  	    PINBlockByteArray = new Array(NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
  	    break;
  	  case 2:
  	    PINBlockByteArray = new Array(2 * NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
  	    break;
  	  case 3:
  	    PINBlockByteArray = new Array(3 * NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
  	    break;
  	  default:
  	    PINBlockByteArray = new Array(4 * NUM_OF_BYTES_IN_FMT2_PIN_BLOCK);
  	}
	PINBlockByteArray = fillByteArray(PINBlockByteArray, PIN_BLOCK_FILL_CHARACTER);

	PINBlockByteArray[0] = FMT_12_CONTROL_BYTE;
	PINBlockByteArray[1] = PINLength;
  	arrayCopy(PinStringByteArray, 0, PINBlockByteArray, 2, PINLength);
	createPINMessage(PINBlockByteArray, RN_String)
  	return;
}

function createPINMessage(pinBlockByteArray, RN_String)
{ 
	var pinMessageArray;
	var pinMessageLength;
	var pinBlockLength;
	var pinMessageVector;
  	var RNStringLength;
	var RNByteLength;
	var maxRandomNumberStringSize;
	var conversionError;
	
  	pinMessageArray = new Array(MAX_MESSAGE_SIZE_IN_BYTES); 	
	pinMessageArray[0] = ONE_PIN_BLOCK_IN_MESSAGE;
	pinMessageLength = 1;

	if (pinBlockByteArray == null) {
  	  return ERR_INVALID_PIN_BLOCK;
	}

	pinBlockLength = pinBlockByteArray.length;
	arrayCopy(pinBlockByteArray, 0, pinMessageArray, pinMessageLength, pinBlockLength);
	pinMessageLength = pinMessageLength + pinBlockLength;

	if (RN_String == null) {
  	  return ERR_INVALID_RANDOM_NUMBER;
	}
  	RNStringLength = RN_String.length;
  	RNByteLength = parseInt((RNStringLength + 1) / 2);
	
    maxRandomNumberStringSize = (MAX_MESSAGE_SIZE_IN_BYTES - pinMessageLength) * NUM_OF_NIBBLES_PER_BYTE;

	if (RNStringLength < MIN_RANDOM_NUMBER_STRING_LENGTH || 
		RNStringLength > maxRandomNumberStringSize ||
	    RNStringLength != (RNByteLength * 2))					
	{
  	  return ERR_INVALID_RANDOM_NUMBER_LENGTH;
	}
	
 	conversionError = convertStringToPackedHexByteArray(RN_String, pinMessageArray, pinMessageLength);
	
	if (conversionError != NO_HEX_CONVERSION_ERRORS) {
  	  return ERR_INVALID_RANDOM_NUMBER;
	}
	pinMessageLength = pinMessageLength + RNByteLength;

	pinMessageVector = new Array(pinMessageLength);
  	for (var index = 0; index < pinMessageLength; index++) { 
	  pinMessageVector[index] = pinMessageArray[index];
  	}
	OAEPEncodedPINMessage(pinMessageVector);
	return;
}

function OAEPEncodedPINMessage(pinMessageArray)
{
	var encodedMsgByteArray = new Array(ENCODED_MESSAGE_SIZE_IN_BYTES);
	var encodedMessageString;
	var encodingParameterString;
	var encMsgArray;

    encodedMsgByteArray = doOAEPEncoding(pinMessageArray);
	encodedMessageString = 	convertToHexString(encodedMsgByteArray);
	encodingParameterString = convertToHexString(P);

	var strPartLengthP = parseInt(encodedMessageString.length / 8);
	P_String = encodingParameterString.toUpperCase();
	
	encMsgArray = encryptMessageRSA(encodedMessageString);

	var diff_len = (RSA_MODULUS_SIZE_IN_BYTES * 2) - encMsgArray.length;
	if (diff_len > 0) {
		for (index = 0; index < diff_len; index++) {
			encMsgArray = '0' + encMsgArray;
		}
	}

	C_String = encMsgArray.toUpperCase();
	
	return;
}

function doOAEPEncoding(pinMessageArray)
{
	var encodedMsgByteArray = new Array(ENCODED_MESSAGE_SIZE_IN_BYTES);
  	var pinMsgLength;
	var offset;
	var numberOfPaddingBytes;

    var pinMsgbyteArray = new Array(MAX_PIN_MESSAGE_SIZE_IN_BYTES);
  	var pHash = new Array(SHA1_HASH_SIZE_IN_BYTES);
  	var DB = new Array(DATA_BLOCK_SIZE_IN_BYTES);
  	var dbMask = new Array(DATA_BLOCK_SIZE_IN_BYTES);
  	var maskedDB = new Array(DATA_BLOCK_SIZE_IN_BYTES);
  	var seed = new Array(SHA1_HASH_SIZE_IN_BYTES);
  	var seedMask = new Array(SHA1_HASH_SIZE_IN_BYTES);
  	var maskedSeed = new Array(SHA1_HASH_SIZE_IN_BYTES);
  	
	if (pinMessageArray == null) {
  	  return ERR_INVALID_PIN_MESSAGE;
	}
  	pinMsgLength = pinMessageArray.length;

  	if (pinMsgLength < MIN_PIN_MESSAGE_SIZE_IN_BYTES || pinMsgLength > MAX_PIN_MESSAGE_SIZE_IN_BYTES) {
  	  return ERR_INVALID_PIN_MESSAGE_LENGTH;
  	}

	P = randomGenerator(ENCODING_PARAMETER_SIZE_IN_BYTES);
	pHash = doHash(P, ENCODING_PARAMETER_SIZE_IN_BYTES);

	fillByteArray(DB, 0x00);			// fill DB with zeroes
  	arrayCopy(pHash, 0, DB, 0, SHA1_HASH_SIZE_IN_BYTES);
  	offset = SHA1_HASH_SIZE_IN_BYTES;
  	numberOfPaddingBytes = DATA_BLOCK_SIZE_IN_BYTES - SHA1_HASH_SIZE_IN_BYTES - pinMsgLength - 1;
	offset += numberOfPaddingBytes;
	DB[offset] = parseInt(0x01);
	offset++;

	copyByteArray(pinMessageArray, pinMsgbyteArray, pinMsgLength);
  	arrayCopy(pinMsgbyteArray, 0, DB, offset, pinMsgLength);

	seed = randomGenerator(RANDOM_SEED_SIZE_IN_BYTES);

	MGF1(seed, dbMask, DATA_BLOCK_SIZE_IN_BYTES);

	xorByteArrays(DB, dbMask, maskedDB);
	
	MGF1(maskedDB, seedMask, SHA1_HASH_SIZE_IN_BYTES);

	xorByteArrays(seed, seedMask, maskedSeed);

  	arrayCopy(maskedSeed, 0, encodedMsgByteArray, 0, SHA1_HASH_SIZE_IN_BYTES);
  	arrayCopy(maskedDB, 0, encodedMsgByteArray, SHA1_HASH_SIZE_IN_BYTES, DATA_BLOCK_SIZE_IN_BYTES);

  	return encodedMsgByteArray;
}

function MGF1(Z, T, l)
{
  	var C = new Array(NUM_OF_BYTES_PER_WORD);
  	var tempArray = new Array(ENCODED_MESSAGE_SIZE_IN_BYTES);
  	var hashArray = new Array(SHA1_HASH_SIZE_IN_BYTES);
  	
  	var maxCount, seedLength, offset, remainingBytes, numberOfBytesToCopy;
  	
  	seedLength = Z.length;
  	maxCount = parseInt(l / SHA1_HASH_SIZE_IN_BYTES);
  	remainingBytes = l - maxCount * SHA1_HASH_SIZE_IN_BYTES;
  	
	if (remainingBytes > 0) {
  	  maxCount++;
  	}
  	
	numberOfBytesToCopy = SHA1_HASH_SIZE_IN_BYTES;
  	
  	for (var counter = 0; counter < maxCount; counter++)
  	{
	  convertIntToByteArray(counter, C, 0);
  	  arrayCopy(Z, 0, tempArray, 0, seedLength);
  	  arrayCopy(C, 0, tempArray, seedLength, NUM_OF_BYTES_PER_WORD);
  	  
	  hashArray = doHash(tempArray, (seedLength + NUM_OF_BYTES_PER_WORD));
	  
	  offset = counter * SHA1_HASH_SIZE_IN_BYTES;
	  
	  if (counter == (maxCount - 1) && remainingBytes > 0) {
	  	numberOfBytesToCopy = remainingBytes;
	  }
			  
  	  arrayCopy(hashArray, 0, T, offset, numberOfBytesToCopy);
  	}
  	return;
}

function xorByteArrays(byteArray1, byteArray2, resultByteArray)
{
  	var index, byteArrayLength;
  	
  	byteArrayLength = byteArray1.length;
  	for (index = 0; index < byteArrayLength; index++) {  		
 	  resultByteArray[index] = parseInt(byteArray1[index] ^ byteArray2[index]);
  	}
  		
    return;
}

function randomGenerator(length)
{
	var randomHexArray = new Array(length);
	var randomNo1;
    var	randomNo2;
    for (var i = 0; i < randomHexArray.length; i++) {
		randomNo1 = Math.floor(Math.random()*16);
		randomNo2 = Math.floor(Math.random()*16);
        randomHexArray[i] = ((randomNo1 << 4) + randomNo2);
    }
	return randomHexArray;
}

function fixPGenerator(fixP)	
{
	var tmpP = new Array(ENCODING_PARAMETER_SIZE_IN_BYTES);	
    for (var i = 0; i < fixP.length; i += 2) {
        tmpP[parseInt(i/2)] = ((parseInt(fixP.charAt(i), HEX_RADIX) << 4) + parseInt(fixP.charAt(i+1), HEX_RADIX));
    }
	return tmpP;
}

function fixSeedGenerator(fixSeed)	
{
	var seed = new Array(ENCODING_PARAMETER_SIZE_IN_BYTES);	
    for (var i = 0; i < fixSeed.length; i += 2) {
        seed[parseInt(i/2)] = ((parseInt(fixSeed.charAt(i), HEX_RADIX) << 4) + parseInt(fixSeed.charAt(i+1), HEX_RADIX));
    }
	return seed;
}

function copyByteArray(srcByteArray, destByteArray, NumOfBytesToCopy)
{
  	for (var index = 0; index < NumOfBytesToCopy; index++) {  		
 	  destByteArray[index] = srcByteArray[index];
  	}
  	return;
}

function encryptMessageRSA(oaepEncMessage)
{
	var encMsgByteArray;

  	if (modulusString == null || publicExponentString == null) {
      return ERR_INVALID_RSA_KEY_LENGTH;
  	}

  	if (oaepEncMessage == null) {
      return ERR_INVALID_ENCODED_MSG_LENGTH;
  	}

	var rsa = new RSAKey();

	rsa.setPublic(modulusString, publicExponentString);

    validateRSAEncInputData(oaepEncMessage.length);

	encMsgByteArray = rsa.encrypt(oaepEncMessage);

	return encMsgByteArray;
}

function validateRSAEncInputData(inputDataLength)
{
	var modulusSizeInBits;
	var maxInputDataSizeInBytes;
    var modulusSizeInBytes = parseInt((modulusString.length + 1) / 2);
    var publicExponentSizeInBytes = parseInt((publicExponentString.length + 1) / 2);

    if ((modulusSizeInBytes != RSA_MODULUS_SIZE_IN_BYTES) || (publicExponentSizeInBytes != RSA_MODULUS_SIZE_IN_BYTES)) {
      return ERR_INVALID_RSA_KEY_LENGTH;
    }

    modulusSizeInBits = modulusSizeInBytes * 8;
    maxOutputDataSizeInBytes = parseInt((modulusSizeInBits + 7) / 8);
    maxInputDataSizeInBytes = maxOutputDataSizeInBytes - 1;

  	if (inputDataLength > (maxInputDataSizeInBytes + 1)) {
      return ERR_INVALID_ENCODED_MSG_LENGTH;
  	}

  	return;
}
