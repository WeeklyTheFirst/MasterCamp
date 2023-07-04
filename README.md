# MasterCamp

RansomWare Protection with CyberShied
#Cybershield - Projet d'antivirus Python
![Copy_of_Cyber-removebg-preview](https://github.com/WeeklyTheFirst/MasterCamp/assets/94228552/948264cc-9bb3-4829-ac2c-4df045fa53ff)


Cybershield est un projet open source d'antivirus développé en Python. Cet antivirus offre trois fonctionnalités principales : le scan de fichiers, le scan d'URLs et une extension Chrome pour le scan d'URLs. Il utilise les bibliothèques requests et tkinters pour son fonctionnement. De plus, il interagit avec les APIs de VirusTotal et de Metadefender en envoyant des requêtes HTML pour l'analyse des fichiers et des URLs.

##Fonctionnalités
###Scan de fichiers : Cybershield permet de scanner des fichiers sur votre système. Il utilise l'API de VirusTotal pour analyser les fichiers à la recherche de menaces potentielles.

###Scan d'URLs : L'antivirus peut également scanner des URLs pour détecter d'éventuels sites malveillants ou compromis. Il utilise l'API de VirusTotal pour effectuer cette analyse.

###Extension Chrome : Cybershield propose une extension Chrome qui permet de scanner les URLs visitées en temps réel. Cette extension communique avec l'antivirus pour obtenir les résultats de l'analyse.

##Prérequis
###Avant d'utiliser Cybershield, assurez-vous d'avoir les éléments suivants installés sur votre système :

Python 3.x
Les bibliothèques Python requests et tkinter

##Installation
###Clonez le dépôt GitHub :

bash
Copy code
git clone https://github.com/votre-utilisateur/cybershield.git
Accédez au répertoire du projet :

bash
Copy code
cd cybershield
###Installez les dépendances requises :

Copy code
pip install -r requirements.txt
Configuration
Avant d'utiliser Cybershield, vous devez configurer les clés d'API nécessaires pour l'interaction avec VirusTotal et Metadefender.

Rendez-vous sur les sites de VirusTotal et de Metadefender pour obtenir vos clés d'API respectives.

Ouvrez le fichier config.py dans un éditeur de texte.

Remplacez les valeurs YOUR_VIRUSTOTAL_API_KEY et YOUR_METADEFENDER_API_KEY par vos clés d'API correspondantes.

##Utilisation
###Lancez l'application :

Copy code
python cybershield.py
L'interface graphique de Cybershield s'ouvrira. Vous pourrez sélectionner les fonctionnalités de scan de fichiers ou d'URLs à partir du menu.

###Pour utiliser l'extension Chrome, suivez les étapes suivantes :

Ouvrez Google Chrome et accédez à chrome://extensions.
Activez le mode développeur en cliquant sur le bouton approprié.
Cliquez sur "Charger l'extension non empaquetée" et sélectionnez le dossier chrome_extension du projet.
L'extension Cybershield apparaîtra dans la liste des extensions installées.
Lorsque vous visitez une URL, l'extension enverra l'URL à l'antivirus pour analyse.
##Contributions
Les contributions sont les bienvenues ! Si vous souhaitez améliorer Cybershield ou ajouter de nouvelles fonctionnalités, veuillez soumettre une demande d'extraction sur GitHub.

##Remarques
Cybershield est un projet en cours de développement. Assurez-vous de consulter régulièrement les mises à jour pour bénéficier des dernières fonctionnalités et améliorations.
L'utilisation de cet antivirus ne garantit pas une protection totale contre les menaces en ligne. Il est recommandé de prendre d'autres mesures de sécurité pour protéger votre système.
##Avertissement
L'utilisation de Cybershield est entièrement sous votre responsabilité. Les développeurs ne peuvent être tenus responsables des dommages causés par l'utilisation de cet antivirus.

##Licence
Cybershield est distribué sous la licence MIT. Consultez le fichier LICENSE pour plus d'informations.

Nous espérons que Cybershield sera utile pour vous ! Si vous avez des questions, des suggestions ou des problèmes, n'hésitez pas à créer une nouvelle issue sur GitHub. Merci de votre soutien !

###L'équipe Cybershield
