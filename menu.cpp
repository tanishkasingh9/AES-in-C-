#include "menu.h"

/*
*	The SBoxes below are bad to use because of cache timing attacks
*	An Attacker can manipulate the cache to get rid of some
*	SBox values which will have to be re-cached, changing
*	the time taken for an access and giving the attacker
*	information on key
*/

const byte SBox[16][16] = {
					{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
					{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
					{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
					{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
					{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
					{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
					{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
					{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
					{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
					{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
					{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
					{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
					{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
					{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
					{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
					{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

const byte InvSBox[16][16] = {
					{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
					{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
					{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
					{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
					{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
					{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
					{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
					{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
					{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
					{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
					{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
					{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
					{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
					{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
					{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
					{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}

};

void Menu::printMenu(){
	std::cout << std::endl;
	std::cout << "This is the sample menu for CSE 539" << std::endl;
	std::cout << "A:\tEncrypt a string" << std::endl;
	std::cout << "B:\tDecrypt a string" << std::endl;
	std::cout << "C:\tEncrypt a string with a random key" << std::endl;
	std::cout << "k:\tGenerate a random 128-bit key" << std::endl;
	std::cout << "q:\tQuit" << std::endl;
	std::cout << std::endl;
}

void Menu::grabInput(){
	char val;
	int error = 0;
	do{
		printMenu();
		std::cin >> val;
		std::cout << std::endl;
		switch(val){
			case 'A':
				error = encrypt(0);
				if(error){
					return;
				}
				break;
			case 'B':
				error = decrypt();
				if(error){
					return;
				}
				break;
			case 'C':
				error = encrypt(1);
				if(error){
					return;
				}
				break;
			case 'k':
			std::cout << "Generating Random 128-bit Key:" << std::endl;
				byte key[4][Nb];
				generateKey(key);
				printState(key);
				break;	
			case 'q':
				std::cout << "Quitting the Program" << std::endl << std::endl;
				break;
			default:
				std::cout << "Input with:\'" << val << "\' is invalid!" << std::endl << std::endl;
				break;
		}

	} while (val != 'q');
}

int Menu::encrypt(int randKey){ //rand key is a boolean which if true, generates a random key for the user
	byte key[4][Nb];
	//STR50-CPP. Guarantee that storage for strings has sufficient space for character data and the null terminator
	//Here a string is used to get input with cin, which prevents buffer overflow and from
	//attackers being able to execute arbituary code.
	std::string str = "";
	unsigned int temp = 0;
	if(randKey){
		generateKey(key);
		std::cout << "Random Key is:" << std::endl;
	}
	else{
		std::cout << "KEY: Enter each of the 16 bytes separated by spaces" << std::endl;
		for(int i = 0; i < Nb; i++){
			for(int j = 0; j < 4; j++){

				std::cin >> str;
				//ERR62-CPP. Detect errors when converting a string to a number
				try{
					temp = std::stoi(str, 0, 16); // i and j are flipped on purpose
				}
				catch(std::invalid_argument e){
					std::cout << "Number Format Error!" << std::endl;
					return 1;
				}
				//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
				//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
				//if the number is out of range, I get undefined behavior
				if(temp < 0 || temp > 255){
					std::cout << "ERROR: one of key's values is out of range 0x00 - 0xFF" << std::endl;
					//exit(1); // violates ERR50-CPP. Do not abruptly terminate the program
					//ERR50-CPP. Do not abruptly terminate the program
					return 1;
				}
				else{
					key[j][i] = (byte)(temp);
				}
			}
		}
		std::cout << "Key is entered as:" << std::endl;
	}

	printStateOneLine(key);

	byte IV[4][Nb]; //IV is randomly generated each time for encryption. It needs to be included with the cipher text
	generateKey(IV);
	std::cout << "Your Random IV is:" << std::endl;
	printStateOneLine(IV);

	byte in[4][Nb]; // represents the current block that is being processesed
	byte prevBlockCipher[4][Nb]; // represents the previous block of generated ciphertext
	int endOfInput = 0; //boolean to know when to stop taking input
	int numBytesLeft = 0; //used for padding the last block
	int blockNum = 1;
	std::cout << "TEXT: Enter each byte separated by spaces, then ## for end of input" << std::endl;
	while(!endOfInput){
		for(int i = 0; i < Nb; i++){
			for(int j = 0; j < 4; j++){
				//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
				//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
				//if the number is out of range, I get undefined behavior
				

				if(endOfInput){
					//put number 
					in[j][i] = (byte)(numBytesLeft);
				}
				else{
					std::cin >> str;
					if(str == "##"){ //end of input
						endOfInput = 1;
						numBytesLeft = 16 - (i*4) - j; //this represents how many bytes are left which then goes
													   //in the rest of the unused bytes
						in[j][i] = (byte)(numBytesLeft);
						continue;
					}

					//ERR62-CPP. Detect errors when converting a string to a number
					try{
						temp = std::stoi(str, 0, 16); // i and j are flipped on purpose
					}
					catch(std::invalid_argument e){
						std::cout << "Number Format Error!" << std::endl;
						return 1;
					}
					if(temp < 0 || temp > 255){
						std::cout << "ERROR: one of plain text's values is out of range 0x00 - 0xFF" << std::endl;
						//exit(1); // violates ERR50-CPP. Do not abruptly terminate the program
						//ERR50-CPP. Do not abruptly terminate the program
						return 1;
					}
					else{
						in[j][i] = (byte)(temp);
					}
				}

			}
		}
		std::cout << "Block Number = " << blockNum << std::endl;
		//printStateOneLine(in);
		if(blockNum == 1){
			//for the first block, the input block is xored with the IV
			//then passed to the cipher function
			AddRoundKey(in, IV);
			Cipher(in, prevBlockCipher, key);
			printStateOneLine(prevBlockCipher);
		}
		else{
			//For any other block, the input block is xored with
			//the previously generated ciphertext block then
			//passed to the cipher function
			AddRoundKey(in, prevBlockCipher);
			Cipher(in, prevBlockCipher, key);
			printStateOneLine(prevBlockCipher);
		}
		blockNum++;
	}
	return 0;
}

int Menu::decrypt(){
	byte key[4][Nb];
	//STR50-CPP. Guarantee that storage for strings has sufficient space for character data and the null terminator
	//Here a string is used to get input with cin, which prevents buffer overflow and from
	//attackers being able to execute arbituary code.
	std::string str = "";
	

	std::cout << "KEY: Enter each of the 16 bytes separated by spaces" << std::endl;
	unsigned int temp = 0;
	for(int i = 0; i < Nb; i++){
		for(int j = 0; j < 4; j++){
			std::cin >> str;

			//ERR62-CPP. Detect errors when converting a string to a number			
			try{
				temp = std::stoi(str, 0, 16); // i and j are flipped on purpose
			}
			catch(std::invalid_argument e){
				std::cout << "Number Format Error!" << std::endl;
				return 1;
			}
			//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
			//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
			//if the number is out of range, I get undefined behavior
			if(temp < 0 || temp > 255){
				std::cout << "ERROR: one of key's values is out of range 0x00 - 0xFF" << std::endl;
				//exit(1);
				//ERR50-CPP. Do not abruptly terminate the program
				return 1;
			}
			else{
				key[j][i] = (byte)(temp);
			}
		}
	}
	std::cout << "Key is entered as:" << std::endl;
	printStateOneLine(key);

	//here IV is entered the exact same way as the key
	byte IV[4][Nb];
	std::cout << "IV: Enter each of the 16 bytes separated by spaces" << std::endl;

	for(int i = 0; i < Nb; i++){
		for(int j = 0; j < 4; j++){

			std::cin >> str;

			//ERR62-CPP. Detect errors when converting a string to a number			
			try{
				temp = std::stoi(str, 0, 16); // i and j are flipped on purpose
			}
			catch(std::invalid_argument e){
				std::cout << "Number Format Error!" << std::endl;
				return 1;
			}
			//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
			//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
			//if the number is out of range, I get undefined behavior
			if(temp < 0 || temp > 255){
				std::cout << "ERROR: one of key's values is out of range 0x00 - 0xFF" << std::endl;
				//exit(1);
				//ERR50-CPP. Do not abruptly terminate the program
				return 1;
			}
			else{
				IV[j][i] = (byte)(temp);
			}
		}
	}

	std::cout << "IV is entered as:" << std::endl;
	printStateOneLine(IV);

	byte in[4][Nb];
	std::cout << "CIPHER: Enter each byte (should be a multiple of 16) separated by spaces, then ## for end of input" << std::endl;
	int endOfInput = 0;
	byte prevBlockCipher[4][Nb]; // represents the previous block of inputted cipher text
	byte output[4][Nb]; // used to fill with generated plaintext
	int blockNum = 1;

	while(!endOfInput){
		for(int i = 0; i < Nb; i++){
			if(endOfInput){ //since ciphertext is already padded, once "##" is read, no padding needs to occur
				break;
			}
				for(int j = 0; j < 4; j++){
					//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
					//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
					//if the number is out of range, I get undefined behavior
					std::cin >> str;
					if(str == "##"){
						endOfInput = 1;
						break;
					}
					//ERR62-CPP. Detect errors when converting a string to a number					
					try{
						temp = std::stoi(str, 0, 16); // i and j are flipped on purpose
					}
					catch(std::invalid_argument e){
						std::cout << "Number Format Error!" << std::endl;
						return 1;
					}
					//NT31-C. Ensure that integer conversions do not result in lost or misinterpreted data
					//here I check to make sure that the number inputted is between 0x00 and 0xFF (0 and 255)
					//if the number is out of range, I get undefined behavior
					if(temp < 0 || temp > 255){
						std::cout << "ERROR: one of cipher text's values is out of range 0x00 - 0xFF" << std::endl;
						//exit(1);
						//ERR50-CPP. Do not abruptly terminate the program
						return 1;
					}
					else{
						in[j][i] = (byte)(temp);
					}
				}
			}
		if(endOfInput){
			break;
		}
		std::cout << "Block Number = " << blockNum << std::endl;
		if(blockNum == 1){
			InvCipher(in, output, key); //the invCipher is used on the given ciphertext
			for(int i = 0; i < 4; i++){ //copy the current cipher block to prevBlockCipher
				for(int j = 0; j < Nb; j++){
					prevBlockCipher[i][j] = in[i][j];
				}
			}
			AddRoundKey(output, IV); //for the first block, the output is xored with the given IV
			printStateOneLine(output);
		}
		else{
			InvCipher(in, output, key);//the invCipher is used on the given ciphertext
			AddRoundKey(output, prevBlockCipher);//for non-first blocks, the output is xored with
												//the previous block of cipher to get the plaintext
			printStateOneLine(output);
			for(int i = 0; i < 4; i++){//once done, copy the current cipher block to prevBlockCipher
				for(int j = 0; j < Nb; j++){
					prevBlockCipher[i][j] = in[i][j];
				}
			}
		}
		blockNum++;
	}
	return 0;
}

void Menu::Cipher(byte in[4][Nb], byte out[4][Nb], byte key[4][Nb]){
	byte state[4][Nb];

	//EXP53-CPP. Do not read uninitialized memory
	//Here, state is created and not read from until
	//determinate values are stored in the array
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			state[i][j] = in[i][j];
		}
	}

	//the following code almost exactly follows the one in the standard document
	//the only difference is that the next 16 byte "key" that is generated
	//each round rather than all beforehand and put into an array.
	AddRoundKey(state, key);
	int numRounds = 10;
	for(int i = 1; i < numRounds; i++){
		SubBytes(state);
		ShiftRows(state);
		MixColumn(state);	
		keyExpansion(key,i); // key is replaced with the next needed key round
		AddRoundKey(state, key);
	}
	SubBytes(state);
	ShiftRows(state);
	keyExpansion(key, 10);
	AddRoundKey(state, key);

	//copy the results to output
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			out[i][j] = state[i][j];
		}
	}
}

void Menu::InvCipher(byte in[4][Nb], byte out[4][Nb], byte key[4][Nb]){
	byte state[4][Nb];
	//EXP53-CPP. Do not read uninitialized memory
	//Here, state is created and not read from until
	//determinate values are stored in the array
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			state[i][j] = in[i][j];
		}
	}


	//since InvCipher requires the last expanded key,
	//all of the keys were generated beforehand
	byte SavedKeys[11][4][4]; //holds all of the expanded key
	for(int j = 0; j < 4; j++){
		for(int k = 0; k < 4; k++){
			SavedKeys[0][j][k] = key[j][k];
		}
	}
	for(int i = 1; i < 11; i++){
		keyExpansion(key, i);
		for(int j = 0; j < 4; j++){
			for(int k = 0; k < 4; k++){
				SavedKeys[i][j][k] = key[j][k];
			}
		}
	}

	//Follows the code given from teh standard document
	AddRoundKey(state, SavedKeys[10]);
	InvShiftRows(state);
	InvSubBytes(state);
	for(int i = 9; i > 0; i--){
		AddRoundKey(state, SavedKeys[i]);
		invMixColumn(state);
		InvShiftRows(state);
		InvSubBytes(state);
	}
	AddRoundKey(state, SavedKeys[0]);

	//copy the results to output
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			out[i][j] = state[i][j];
		}
	}
}

void Menu::MixColumn(byte state[4][Nb]){
	/*
	In MixColumn() Transformation, the bytes are multiplied with a constant matrice during decryption.
	*/
	/*
		By using the property of GF(2^8) multiplicative and additive properties, 
		we were able to eliminate the need of a repetitive array lookup.
		
		We decreased the number of XORs needed so as to decrease complexity and improve the implementation time.
	*/
	byte tempArray[4] = {0,0,0,0};
	for(int i=0;i<Nb; i++){
	tempArray[0]=Mult02(state[0][i])^Mult02(state[1][i])^state[1][i]^state[2][i]^state[3][i];
	tempArray[1]=state[0][i]^Mult02(state[1][i])^Mult02(state[2][i])^state[2][i]^state[3][i];
	tempArray[2]=state[0][i]^state[1][i]^Mult02(state[2][i])^Mult02(state[3][i])^state[3][i];
	tempArray[3]=Mult02(state[0][i])^state[0][i]^state[1][i]^state[2][i]^Mult02(state[3][i]);

	state[0][i]=tempArray[0];
	state[1][i]=tempArray[1];
	state[2][i]=tempArray[2];
	state[3][i]=tempArray[3];
	}

}

byte Menu::Mult02(byte b){ //used in Mixcolumn and invMixColumn
	b = ((0x80 & b) == 0x80)? (b << 1) ^ 0x1B : b << 1;
	return b;	
}


void Menu::invMixColumn(byte state[4][Nb]){
	/*
	In invMixColumn() Transformation, the bytes are multiplied with a constant matrice during decryption.
	*/
	/*
		By using the property of GF(2^8) multiplicative and additive properties, 
		we were able to eliminate the need of a repetitive array lookup.
		
		We decreased the number of XORs needed so as to decrease complexity and improve the implementation time.
	*/
	byte tempArray[4] = {0,0,0,0};

	for(int i=0;i<Nb; i++){

	tempArray[0] = mult(state[0][i], 14) ^ mult(state[1][i], 11) ^ mult(state[2][i], 13) ^ mult(state[3][i], 9);
	tempArray[1] = mult(state[0][i], 9) ^ mult(state[1][i], 14) ^ mult(state[2][i], 11) ^ mult(state[3][i], 13);
	tempArray[2] = mult(state[0][i], 13) ^ mult(state[1][i], 9) ^ mult(state[2][i], 14) ^ mult(state[3][i], 11);
	tempArray[3] = mult(state[0][i], 11) ^ mult(state[1][i], 13) ^ mult(state[2][i], 9) ^ mult(state[3][i], 14);

	state[0][i]=tempArray[0];
	state[1][i]=tempArray[1];
	state[2][i]=tempArray[2];
	state[3][i]=tempArray[3];
	}

}

byte Menu::mult(byte b, int m){
	//MSC52-CPP. Value-returning functions must return a value from all exit paths
	//before, there was just the switch case, but if none of the cases
	//were met, then nothing would get returned
	//even though this function is always being called with known values,
	//a return statement is needed for all possible paths.
	switch(m){
	case 9  :return  Mult02(Mult02(Mult02(b)))^b;	break;
	case 11 :return  Mult02(Mult02(Mult02(b))^b)^b;	break;
	case 13 :return  Mult02(Mult02(Mult02(b)^b))^b;	break;
	case 14 :return  Mult02(Mult02(Mult02(b)^b)^b);	break;
	}

	return 0xFF;
}

void Menu::AddRoundKey(byte state[4][Nb], byte key[4][Nb]){
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			state[i][j] = state[i][j] ^ key[i][j];
		}
	}
}

byte Menu::subByte(byte b){

    byte rowMask = 0xF0;//used to get the first 4 bits of the byte
	byte colMask = 0x0F;//used to get the last  4 bits of the byte

	int row = 0;
	int col = 0;

    row = (int)(rowMask & b) / 16; // need to divide by 16 to get the 4 MSB 
	col = (int)(colMask & b);
	b = SBox[row][col];

    return b;

}

void Menu::SubBytes(byte state[4][Nb]){
	/*
		The S-box used in the SubBytes() transformation is presented in hexadecimal form in Fig. 7.
		For example, if s1,1 ={53}, then the substitution value would be determined by the intersection
		of the row with index ‘5’ and the column with index ‘3’ in Fig. 7. This would result in s1,1' having a value of {ed}. 
	*/
	byte rowMask = 0xF0;//used to get the first 4 bits of the byte
	byte colMask = 0x0F;//used to get the last  4 bits of the byte
	int row = 0;
	int col = 0;
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			row = (int)(rowMask & state[i][j]) / 16; // need to divide by 16 to get the 4 MSB  bits
			col = (int)(colMask & state[i][j]);
			state[i][j] = SBox[row][col];
		}
	}
}

void Menu::InvSubBytes(byte state[4][Nb]){
	/*
	InvSubBytes() is the inverse of the byte substitution transformation, 
	in which the inverse Sbox is applied to each byte of the State.
	*/
	byte rowMask = 0xF0;//used to get the first 4 bits of the byte
	byte colMask = 0x0F;//used to get the last  4 bits of the byte
	int row = 0;
	int col = 0;
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			row = (int)(rowMask & state[i][j]) / 16; // need to divide by 16 to get the 4 MSB  bits
			col = (int)(colMask & state[i][j]);
			state[i][j] = InvSBox[row][col];
		}
	}
}

void Menu::ShiftRows(byte state[4][Nb]){
	/*
	In the ShiftRows() transformation, the bytes in the last three rows 
	of the State are cyclically shifted over different 
	numbers of bytes (offsets). The first row, r = 0, is not shifted. 

	S(r,c) = s(r,(c + shift (r, Nb)) mod Nb)
	shift(1,4) = 1; shift(2,4) = 2 ; shift(3,4) = 3
	shift(r,c) = r.
	*/
	byte tempArr[4] = {0,0,0,0};

	for(int r = 0; r < 4; r++){
		
		for(int c = 0; c < Nb; c++){
			tempArr[c] = state[r][(c + r) % Nb]; //s(r,(c + shift (r, Nb)) mod Nb)
		}
		for(int c = 0; c < Nb; c++){
			state[r][c] = tempArr[c];
		}
	}
	
}

void Menu::InvShiftRows(byte state[4][Nb]){
	/*
	InvShiftRows() is the inverse of the ShiftRows() transformation. The bytes in the last
	three rows of the State are cyclically shifted over different numbers of bytes (offsets). The first
	row, r = 0, is not shifted. The bottom three rows are cyclically shifted by Nb - shift(r, Nb)
	bytes, where the shift value shift(r,Nb) depends on the row number, and is given in equation
	S(r, (c+shift(r,Nb))mod Nb) = 	S(s,c)
	*/
	byte tempArr[4] = {0,0,0,0};

	for(int r = 0; r < 4; r++){
		
		for(int c = 0; c < Nb; c++){
			tempArr[(c + r) % Nb] = state[r][c]; //s(r,(c + shift (r, Nb)) mod Nb)

		}
		for(int c = 0; c < Nb; c++){
			state[r][c] = tempArr[c];
		}
	}
}

void Menu::subWord(byte word[4]){
	for(int i = 0; i < 4; i++){
        word[i] = subByte(word[i]);
	}
}

void Menu::rotWord(byte word[4]){
    byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void Menu::keyExpansion(byte key[4][Nb],int i){
	byte Rcon[11] = {	0x00,
						0x01,0x02,0x04,0x08,0x10,
						0x20,0x40,0x80,0x1b,0x36
					};

	// First column
	key[0][0] ^= subByte(key[1][3])^ Rcon[i];
	key[1][0] ^= subByte(key[2][3]);
	key[2][0] ^= subByte(key[3][3]);
	key[3][0] ^= subByte(key[0][3]);

	for (int col = 1; col < Nb; col++){
		for (int row = 0; row < 4; row++){
			key[row][col] ^= key[row][col-1];
		}
	}
}

void Menu::printByte(byte b){
	std::bitset<8> x(b);
	std::cout << x;
}

void Menu::printSBox(){
	for(int i = 0; i < 16; i++){
		for(int j = 0; j < 16; j++){
			int temp = (int)SBox[i][j];
			std::bitset<16> x(temp);
			//std::cout << x << "\t";
			std::cout << std::hex << temp << "\t";
		}
		std::cout << std::endl;
	}
};

void Menu::printState(byte state[4][Nb]){
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			int temp = (int)state[i][j];
			std::bitset<16> x(temp);
			//std::cout << x << "\t";
			std::cout << std::hex << temp << "\t";
		}
		std::cout << std::endl;
	}
}

void Menu::printStateOneLine(byte state[4][Nb]){
	for(int i = 0; i < 4; i++){
		for(int j = 0; j < Nb; j++){
			int temp = (int)state[j][i];
			std::bitset<16> x(temp);
			//std::cout << x << "\t";
			std::cout << std::hex << temp << "\t";
		}
		
	}
	std::cout << std::endl;
}

void Menu::generateKey(byte key[4][Nb]){
// MSC50-CPP. Do not use std::rand() for generating pseudorandom numbers
// MSC51-CPP. Ensure your random number generator is properly seeded

//for this method, 4 32bit numbers are generated and split into 4 bytes each
//and each byte is put into the array given.
	std::mt19937 engine(std::random_device{}());
	engine.discard(700000);
	unsigned int rand1 = engine();
	unsigned int rand2 = engine();
	unsigned int rand3 = engine();
	unsigned int rand4 = engine();
	
	unsigned int mask1 = 0xFF000000;
	unsigned int mask2 = 0x00FF0000;
	unsigned int mask3 = 0x0000FF00;
	unsigned int mask4 = 0x000000FF;

	unsigned int randArr[4]  = { rand1, rand2, rand3, rand4};
	for(int i = 0; i < 4; i++){
		key[i][0] = (randArr[i] & mask1)/16777216;
		key[i][1] = (randArr[i] & mask2)/65536;
		key[i][2] = (byte)((randArr[i] & mask3)/256);
		key[i][3] = (byte)(randArr[i] & mask4);
	}
}
