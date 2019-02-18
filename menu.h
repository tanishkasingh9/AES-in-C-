#ifndef __MENU__H__
#define __MENU__H__

#include <iostream>
#include <string>
#include <fstream>
#include <bitset>
#include <random>

const int Nb = 4; //Number of columns (32-bit words) comprising the State. For this standard, Nb = 4. 
const int Nk = 4; //Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8. (Also see Sec. 6.3.) 
const int Nr = 10; //Number of rounds, which is a function of Nk and Nb (which is fixed). For this standard, Nr = 10, 12, or 14. (Also see Sec. 6.3.) 

//using byte = unsigned char;
typedef unsigned char byte;

class Menu {
	public:
		void printMenu();
		void grabInput();
		int encrypt(int randKey);
		int decrypt();
		void Cipher(byte in[4][Nb], byte out[4][Nb], byte key[4][Nb]);
		void InvCipher(byte in[4][Nb], byte out[4][Nb], byte key[4][Nb]);
		void MixColumn(byte state[4][Nb]);
		byte Mult02(byte b);
		void invMixColumn(byte state[4][Nb]);
		byte mult(byte b, int m);
		void AddRoundKey(byte state[4][Nb], byte key[4][Nb]);
		byte subByte(byte b);
		void SubBytes(byte state[4][Nb]);
		void InvSubBytes(byte state[4][Nb]);
		void ShiftRows(byte state[4][Nb]);
		void InvShiftRows(byte state[4][Nb]);
		void subWord(byte word[4]);
		void rotWord(byte word[4]);
		void keyExpansion(byte word[4][Nb], int);
		void printByte(byte b);
		void printSBox();
		void printState(byte state[4][Nb]);
		void printStateOneLine(byte state[4][Nb]);
		void generateKey(byte key[4][Nb]);		
};

#endif
