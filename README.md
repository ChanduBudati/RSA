# RSA

This project/ implementation is neigther the fastest nor the safest way to code RSA.
My aim was to implement a readable and easy to understant version of this algorithm.

Project structure:
1. All the code is in single python3 file named rsa.py
2. Perviously generated keys are stored in a text file named keys-XX.txt, keys.txt contains the key that are currently in use
	a. 1st line is e, secound is d and third is n
3. program reads the message in plaintext.txt and file encrypts it.
4. the ciphertext is stored in ciphertext.txt file.
5. for decryption ciphertext is read from the same file(ciphertext.txt) and the resulting plaintext is printed on the screen(also stored in plaintext.txt).

To execute the program just use the below command or double click on rsa.py:
python3 rsa.py
- you can then choose one fo the options to either encrypt , decrypt or generate keys.
