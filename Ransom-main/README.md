## Ransom

Ransom est un programme réalisé dans le cadre du cours de dévelopement. Il a pour vocation de présenter le fonctionnement d'un ransomware. Son utilisation est donc a des fins purement éducative. 

#Compilation :

Utilisez le package GCC afin de compiler les dossiers ransom.c et ransomlib.c. Le paramètre -lcrypto va lier le projet à la librairie crypto. (cette librairie est créer au téléchargement de openssl.

```bash
gcc -o ransom ransom.c ransomlib.c -lcrypto
gcc -o server server.c
```

#Utilisation :

Une fois le programme compiler, il est possible de le lancer grace à la fonction ./ransom. Cette fonction ne sert qu'a utilisé le fichier executable crée dans le dossier courant. (créer un alias ou déplacer l'executable dans les /usr/local/bin peut être une bonne solution pour pouvoir utilisé le programme sans nécésserement qu'il soit dans le dossier courant.) Les exemples suivant assume que l'exécutable s'appelle ransom et se trouve dans le dossier courant.

```bash

#chiffrement d'un dossier 
./ransom [DIRECTORY]

#déchiffrement d'un dossier 
./ransom [DIRECTORY] -d [KEY] [IV]
```

Si le programme c'est lancé correctement : les fichiers à l'interieur du dossier mentionné a belle et bien été chiffré ou déchiffrer. 
Si ce n'est pas le cas : vérifier la sortie d'erreur. Un fichier peut ne pas avoir été chiffré pour plusieurs raison par exemple la taille qui est limité à 1GB ou encore un fichier qui portait déjà une extension .Pwnd. Un autre cas d'erreur est qu'aucun serveur n'écoutait pour récupérer la clé. 

#Instalation requise : 

le programme Ransom utilise la bibliothèque openssl. Si elle n'est pas encore installer sur le pc cible, il sera nécessaire de l'installer grace à votre gestionnaire de paquet. 
