# AES-in-C++


# How to Compile
1. Clone the repo and type `g++ CSE539Project.cpp menu.cpp`

2. Run with `./a.out`

# Menu

A - Encryption. You are first prompted to enter the key which will be each byte separated by a space. You then input the text the same way. It'll output the cipher text to the console.

B - Decryption. You are first prompted to enter the key which will be each byte separated by a space. You then input the cipher text the same way. It'll output the plain text to the console.

t - Used right now to test the operations of the byte array

q - Quit the program

# Example Inputs

Encryption:

```
A

2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34

q
```

Decryption:

```
B

2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32

q

```
