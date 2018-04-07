#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 	16
#define CMAC_SIZE  	16
#define TRUE 		 1
#define FALSE 		 0


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void myencrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    		    unsigned char **, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    		unsigned char **, int);
void gen_cmac	(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac	(unsigned char *, unsigned char *);
unsigned char* readPlaintext(char*);

/* Global variables */
unsigned char *globalkey = NULL;
int ssize;
int ciphertext_len;
int blvr = 0;


/* TODO Declare your function prototypes here... */
void write_file(char * file,unsigned char * text,int length, int mode);




/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
		"*** Optionally you add '1' (without '') as last argument to enable debug mode ***\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {	
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */



void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{

	/* TODO Task A */
		const unsigned char *salt = NULL;
		const EVP_CIPHER *cipher;
		const EVP_MD *hash_function = NULL;

	/* select a cipher mode and key size */
		if(bit_mode == 128) 
			cipher = EVP_get_cipherbyname("aes-128-ecb");
		else if(bit_mode == 256) 
			cipher = EVP_get_cipherbyname("aes-256-ecb");
		else{
			fprintf(stderr, "Error in cipher param.\n"); exit(1);
		}

	/* select a hash function before calling the keygen */
		globalkey = malloc(bit_mode/8);
		hash_function = EVP_get_digestbyname("sha1");
	/* convert the password bytes to key */
		if(EVP_BytesToKey(cipher, hash_function, salt,(unsigned char*) password,  strlen((char *)password), 1, globalkey, iv) ==0 ) {
			fprintf(stderr, "Error in EVP_BytesToKey in keygen.\n"); exit(1);
		}
			
		if(blvr)
			print_hex(globalkey,bit_mode/8);
}


/*
 * Encrypts the data
 */
void
myencrypt(	
	unsigned char 	*	plaintext, 
			  int 		plaintext_len, 
	unsigned char 	*	key,
	unsigned char 	*	iv, 
	unsigned char 	**	ciphertext, 
			  int 		bit_mode		
	)
{

	/* TODO Task B */
	

		EVP_CIPHER_CTX context;
		const EVP_CIPHER *cipher;
		unsigned char* cipher_;
		int cipher_len;
		int cipher_len_final_addition;

		if(blvr){
	 		printf("__START OF ENCRYPT\n");
			print_hex(plaintext, plaintext_len);
		}

		if(bit_mode == 128) 
			cipher = EVP_get_cipherbyname("aes-128-ecb");
		else if(bit_mode == 256) 
			cipher = EVP_get_cipherbyname("aes-256-ecb");
		else{
			fprintf(stderr, "Error in cipher param.\n"); exit(1);
		}

		if(blvr)
			printf("before init\n");

	/* create a new encryption context */
		EVP_CIPHER_CTX_init(&context);
		if(blvr)
			printf("before init\n");

	/* initialize with appropriate mode and key size */
		if(EVP_EncryptInit_ex(&context,cipher,NULL,key,iv)==0){
			fprintf(stderr, "Error in EVP_EncryptInit_ex in encrypt.\n"); exit(1);
		}

	/* update the ciphertext */
		cipher_ 		= malloc(plaintext_len + BLOCK_SIZE);

		if(blvr){
			printf("before update\n");
			printf("%d\n", plaintext_len);
		}

		if(EVP_EncryptUpdate(&context, cipher_, &cipher_len ,plaintext, plaintext_len)==0 ){
			fprintf(stderr, "Error in EVP_EncryptUpdate, first cipher, in encrypt.\n"); exit(1);
		}

		if(blvr)
			printf("before finalize\n");

	/* finalize the encryption */
		if(EVP_EncryptFinal_ex(&context, &cipher_[cipher_len], &cipher_len_final_addition)==0){
			fprintf(stderr, "Error in EVP_EncryptFinal_ex, second cipher, in encrypt.\n"); exit(1);
		}

		if(blvr)
			printf("before ciphertext_malloc\n");

		ciphertext_len = cipher_len + cipher_len_final_addition;
		*ciphertext = malloc(ciphertext_len);
		memcpy(*ciphertext, cipher_, ciphertext_len);
		
		if(blvr){
			printf("ciph_len: %d\n", ciphertext_len);
			print_hex(*ciphertext,ciphertext_len);
        	printf("____END OF ENCRYPT \n");
		}
		


	/* free the context */ 
	 EVP_CIPHER_CTX_cleanup(&context);

}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(	
	unsigned char 	*	ciphertext, 
			  int 		ciphertext_len, 
	unsigned char 	*	key,
	unsigned char 	*	iv, 
	unsigned char	**	plaintext, 
			  int 		bit_mode		
	)
{
	int plaintext_len;
	unsigned char* plain_;
	int plain_len;
	int plain_len_final_addition = 16;

	plaintext_len = 0;

	/*TODO Task C */
		EVP_CIPHER_CTX context;
		const EVP_CIPHER *cipher;

		if(blvr){
			printf("__START OF DECRYPT\n");
			print_hex(ciphertext,ciphertext_len);
		}

		if(bit_mode == 128) 
			cipher = EVP_get_cipherbyname("aes-128-ecb");
		else if(bit_mode == 256) 
			cipher = EVP_get_cipherbyname("aes-256-ecb");
		else{
			fprintf(stderr, "Error in cipher param.\n"); exit(1);
		}
		if(blvr)
			printf("before dec init\n");
			
	/* initialize with appropriate mode and key size */
		EVP_CIPHER_CTX_init(&context);

		if(EVP_DecryptInit_ex(&context, cipher, NULL, key, iv)==0){
				fprintf(stderr, "Error in EVP_DecryptInit_ex in dencrypt.\n"); exit(1);
			}
		if(blvr)
			printf("before mallonc\n");			
		plain_ = malloc(ciphertext_len + BLOCK_SIZE);

		if(blvr)
			printf("before dec update\n");

	/* update the plaintext */
		if(EVP_DecryptUpdate(&context, plain_, &plain_len ,ciphertext, ciphertext_len)==0 ){
			fprintf(stderr, "Error in EVP_DecryptUpdate, first plaintext, in encrypt.\n"); exit(1);
		}
		if(blvr){
			printf("before dec finalize \n");
			printf("%d \n", plain_len);
			print_string(plain_, plain_len);
		}

	/* finalize the dencryption */
		if(EVP_DecryptFinal_ex(&context, &plain_ [plain_len], &plain_len_final_addition)==0){
			fprintf(stderr, "Error in EVP_DecryptFinal_ex, second plaintext, in encrypt.\n"); exit(1);
		}
		plaintext_len = plain_len + plain_len_final_addition;
		*plaintext = malloc(plaintext_len);
		memcpy(*plaintext, plain_, plaintext_len);
		
		if(blvr)
			print_string(*plaintext,plaintext_len);

	/* free the context */
		EVP_CIPHER_CTX_cleanup(&context);

		if(blvr)
			printf("__END OF DECRYPT\n");
		return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(	
	unsigned char 	*	data, 
		   size_t 		data_len, 
	unsigned char 	*	key, 
	unsigned char 	*	cmac, 
			  int 		bit_mode
	)
{

	/* TODO Task D */
		const EVP_CIPHER *cipher;
		size_t cmac_new_size;
		int keysize;

		if(blvr){
			printf("__START OF GEN_CMAC\n");
			print_string(data, data_len);
		}

	/* Create a new CMAC context */
		CMAC_CTX *cmac_new_context = CMAC_CTX_new();

	/* Initialize (mode/key size)*/
		if(bit_mode == 128){
			cipher = EVP_get_cipherbyname("aes-128-ecb");
			keysize = 16;
		}
		else if(bit_mode == 256) {
			cipher = EVP_get_cipherbyname("aes-256-ecb");
			keysize = 32;
		}
		else{
			fprintf(stderr, "Error in cipher param.\n"); exit(1);
		}

		if(CMAC_Init(cmac_new_context, key, keysize, cipher, NULL)==0){
			fprintf(stderr, "Error in CMAC_Init.\n"); exit(1);
		}
	/* Update CMAC */
		if(CMAC_Update(cmac_new_context, data, data_len)==0){
			fprintf(stderr, "Error in CMAC_Update.\n"); exit(1);
		}
	/* Finalize CMAC */
		if(CMAC_Final(cmac_new_context , cmac, &cmac_new_size)==0){
			fprintf(stderr, "Error in CMAC_Final.\n"); exit(1);
		}
	/* Free the context */
		CMAC_CTX_free (cmac_new_context);
		keysize = -1;
		cipher = NULL;


		if(blvr)
				printf("__END OF GEN_CMAC\n");

}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *first, unsigned char *second)
{
	/* TODO Task E */
	/* The CMAC appended at the end of the message and has a fixed size */
	/* Decrypt the message and save the CMAC */
	/* Recalculate the CMAC as when generating it */
	/* Compare the two CMACs*/
	int i;
	for(i = 0; i < CMAC_SIZE; i++){
		if(first[i] != second[i])
			return FALSE;
	}
	return TRUE;
}



/* TODO Develop your functions here... */

int
verify_wrapper(			  	  
			  int 		message_len, 
	unsigned char	*	message,
			  int 		bit_mode,
			 char   *   outfile
	)
{
	int plaintext_len;
	unsigned char * cmac;
	unsigned char * cmac_2;
	unsigned char * ciphertext;
	unsigned char * plaintext;
	
	
	if(blvr){
		printf("__START OF VERIFY_MAC\n");
		printf("%d\n", message_len);
	}


	/* The CMAC is appended at the end of the message and has a fixed size */
		cmac 		= malloc(CMAC_SIZE);
		ciphertext 	= malloc(message_len - CMAC_SIZE);
		plaintext 	= malloc(message_len - CMAC_SIZE);

		memcpy(cmac, &message[message_len - CMAC_SIZE], CMAC_SIZE);
		if(blvr)
			print_hex(cmac, CMAC_SIZE);
		
		memcpy(ciphertext,message,message_len - CMAC_SIZE);

	/* Decrypt the message and save the CMAC */
		plaintext_len = decrypt(ciphertext, message_len - CMAC_SIZE, globalkey, NULL, &plaintext, bit_mode);

	/* Recalculate the CMAC as when generating it */
		cmac_2 = malloc(CMAC_SIZE);
		gen_cmac(plaintext, strlen((const char *)plaintext), globalkey, cmac_2, bit_mode);
		
		if(blvr){
			print_hex(cmac_2,	CMAC_SIZE);
			print_hex(cmac, 	CMAC_SIZE);
		}

		if(blvr){
			printf("END OF VERIFY_MAC\n");
		}
		// return verify_cmac(cmac, cmac_2);

		if(verify_cmac(cmac, cmac_2)) { 
			write_file(outfile, plaintext, plaintext_len, 0);
			return TRUE;
		}
		return FALSE;
}


unsigned char *
readPlaintext(char	*	filename)
{
    int    chr;
    unsigned int i;
	unsigned char* string;
	FILE* file;
	file = fopen(filename, "r");

    i   = 0;
	string = malloc(ssize*(sizeof(char)));
    chr = fgetc(file);
    while ((chr != EOF))
    {
		if(i>=ssize){ 
			ssize+=ssize;
			string = realloc(string,ssize);
		}
        string[i++] = chr;
        chr         = fgetc(file);
    }
    if (i == 0)
        return NULL;
    string[i] = '\0';
	fclose(file);
    return string;
}

int 
readByteText(char * filename,unsigned char **buffer){

	FILE *fp;
	int filelen;

	fp = fopen(filename, "rb");
	if(fp == NULL){
		fprintf(stderr, "Error in write_file.\n"); 
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);          
	filelen = ftell(fp);             
	rewind(fp);                      

	*buffer = malloc(filelen + 1); 
	fread(*buffer, filelen, 1, fp); 
	fclose(fp);
    return filelen;
}


void 
write_file(char * file,unsigned char * text,int length, int mode){
	if(blvr)
		printf("__START WRITE FILE\n");
	FILE *fp; 
	if(mode){
		if(blvr) printf("writing bytes...\n");
		fp = fopen(file, "wb");
	}
	else{
		if(blvr) printf("writing text...\n");
		fp = fopen(file, "w");
	}
	if(fp == NULL){
		fprintf(stderr, "Error in write_file.\n"); 
		exit(-1);
	}
	// fwrite(address_data,size_data,numbers_data,pointer_to_file);
	fwrite(text, sizeof(unsigned char) , length , fp);
	fclose(fp);
	if(blvr)
		printf("\n__END OF WRITE FILE\n");
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the ivenput file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;
	ssize = 512;


	/* My Arguments */
	int plaintext_len;
	int size_return;
	unsigned char* readplaintext = NULL;
	unsigned char* ciphertext = NULL;
	unsigned char* plaintext = NULL;
	unsigned char* cmac = NULL;
	unsigned char* concatenated = NULL;
	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}	


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);
	

	

	/* TODO Develop the logic of your tool here... */

	/* Custom Debug Mode */
	if( argc == 11 && atoi(argv[argc-1])==1){
		printf("debuging...\n");
		blvr = 1;
	}




	/* Initialize the library */
	OpenSSL_add_all_algorithms();



	/* Keygen from password */
	keygen(password, NULL, NULL, bit_mode);
	/* Operate on the data according to the mode */
	switch (op_mode) {
		
		/* encrypt */
		case 0:
			if(blvr)
				printf("op_mode 0, encrypt\n");
			
			readplaintext 	= readPlaintext(input_file);
			myencrypt(readplaintext, strlen((const char*)readplaintext) , globalkey, NULL, &ciphertext, bit_mode);

			if(blvr)
				print_hex(ciphertext, ciphertext_len);

			write_file(output_file,ciphertext, ciphertext_len, 1);

			if(blvr){
				printf("Decrypting instantly the encrypted file...\n" );
				plaintext_len = decrypt(ciphertext, ciphertext_len, globalkey, NULL, &plaintext, bit_mode);
			}
			break;
		
		/* decrypt */
		case 1:
			if(blvr)
				printf("op_mode 1, decrypt\n");
			size_return = readByteText(input_file,&ciphertext);

			plaintext_len = decrypt(ciphertext, size_return , globalkey, NULL, &plaintext, bit_mode);
			/* write mode 0: plaintext */
			write_file(output_file, plaintext, plaintext_len, 0);
			break;
	
		/* sign */
		case 2:
			if(blvr)
				printf("op_mode 2, sign\n");
			readplaintext = readPlaintext(input_file);

			cmac = malloc(CMAC_SIZE);
			gen_cmac(readplaintext, strlen((const char *)readplaintext), globalkey, cmac, bit_mode);
         	myencrypt(readplaintext, strlen((const char *)readplaintext), globalkey, NULL, &ciphertext, bit_mode);

			concatenated = malloc(ciphertext_len + CMAC_SIZE);
			/* copy ciphertext */
			memcpy(concatenated, ciphertext, ciphertext_len);
			/* copy cmac after ciphertext */
			memcpy((concatenated + ciphertext_len),cmac, CMAC_SIZE);
			/* write mode 1: byte */
			write_file(output_file, concatenated ,ciphertext_len + CMAC_SIZE , 1);

			break;
		
		/* verify */ 
		case 3:
			if(blvr)
				printf("op_mode 3, verify\n");
			size_return = readByteText(input_file, &ciphertext);
			if(verify_wrapper(size_return, ciphertext, bit_mode, output_file)==1){ printf("Verified\n");}
			else printf("Verification Failed\n");		

			break;

		default:
			printf("not 0-3 op_mode");
		}
		


	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);



	/* END */
	return 0;
}
