### Description ###

<!--There are 4 modes available:
-->
#### Modes ####

`encrypt`
   
    - Based on the mode selected from the user (128/256) the given plaintext
    gets encrypted using a key derived from the provided password. 
    - EVP_EncryptFinal_ex handles the encrpytion and padding of the "final" data.
    - The encrypted message (ciphertext) is saved.

`dencrypt`

    - Based on the mode selected from the user (128/256) the given ciphertext
    gets dencrypted using a key derived from the provided password.
    - EVP_DecryptFinal_ex handles the "final" data this time.
    - The dencrypted message (plaintext) is saved.

`sign`

    - Based on the mode selected from the user (128/256) the given plaintext gets 
    an authentication code using a key derived from the provided password.
    - Said plaintext gets encrypted.
    - The authentication code is concatenated at the tail of the plaintext 
    - The whole message gets stored in a file.

`verify` (verify\_wrapper, not verify\_cmac)

    - Disassembles the authentication code and ciphertext from the message.
    - Decrypts the ciphertext.
    - Generates a new authentication code for the decrypted ciphertext.
    - Checks if the second CMAC is the same as the one from the first step, in case 
    of which it returns TRUE, otherwise False
    
    
#### Example ####
One can add an optional argument '1' at the end of the command to enable debug mode.

    example:
    ./assign_1 -i ../files/hy457_verifyme_128.txt -o ver128.txt -p hy457 -b 128 -v 1

<!--
/* Answer */
    1. decryptme_256.txt is provided
    2. hy457_encryptme_128.txt is provided
    3. verifyme_128.txt is provided.
    4. Neither hy457_verifyme_256.tx, nor hy457_verifyme_128.txt, where verified.
    On the other hand the signed from step 3 file was verified.
-->



