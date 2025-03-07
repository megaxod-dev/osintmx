# OsintMx

Un outil professionnel en ligne de commande pour la collecte d'informations OSINT (Open Source Intelligence).
Compatible avec Windows, Linux, macOS et Termux (Android).

## Installation

Le projet est installé dans le dossier `OsintMx` sur votre bureau.

### Structure du projet
```
Desktop/
└── OsintMx/               # Dossier principal du projet
    ├── osintmx.py        # Script principal
    ├── requirements.txt  # Dépendances Python
    ├── README.md        # Documentation
    └── OsintMx_Results/ # Résultats des analyses
```

### Windows/Linux/macOS
```bash
# Se placer dans le dossier du projet
cd ~/Desktop/OsintMx

# Installer les dépendances
pip install -r requirements.txt
```

### Termux (Android)
```bash
# Installer Python et les dépendances nécessaires
pkg update && pkg upgrade
pkg install python git

# Se placer dans le dossier du projet
cd ~/Desktop/OsintMx

# Installer les dépendances
pip install -r requirements.txt
```

## Fonctionnalités

- 🌐 Analyse de domaines
  - Informations WHOIS complètes
  - Enregistrements DNS (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Vérification des enregistrements de sécurité

- 📱 Analyse de numéros de téléphone
  - Validation du format
  - Identification du pays
  - Détection de l'opérateur
  - Type de ligne (mobile/fixe)
  - Formatage international et national

- 📧 Analyse d'adresses email
  - Validation du format
  - Vérification des serveurs de messagerie
  - Analyse des enregistrements SPF et DMARC
  - Vérification du domaine

- 🌍 Analyse d'adresses IP
  - Géolocalisation détaillée
  - Identification de l'ISP
  - Recherche DNS inverse
  - Informations réseau

## Utilisation

```bash
python osintmx.py [-h] [-d DOMAIN] [-p PHONE] [-e EMAIL] [-i IP]

Arguments:
  -h, --help            Affiche l'aide
  -d DOMAIN, --domain DOMAIN
                        Domaine à analyser
  -p PHONE, --phone PHONE
                        Numéro de téléphone à analyser (avec indicatif pays, ex: +33612345678)
  -e EMAIL, --email EMAIL
                        Adresse email à analyser
  -i IP, --ip IP       Adresse IP à analyser
```

## Exemples

Analyse d'un domaine :
```bash
python osintmx.py -d example.com
```

Analyse d'un numéro de téléphone :
```bash
python osintmx.py -p +33612345678
```

Analyse d'une adresse email :
```bash
python osintmx.py -e user@example.com
```

Analyse d'une adresse IP :
```bash
python osintmx.py -i 8.8.8.8
```

## Caractéristiques

- Interface professionnelle rouge et blanche
- Compatible avec Termux sur Android
- Sauvegarde automatique des résultats
- Nettoyage automatique de l'écran
- Animations de chargement adaptatives

## Dépendances

- requests : Requêtes HTTP
- beautifulsoup4 : Analyse HTML
- python-whois : Informations WHOIS
- dnspython : Analyse DNS
- phonenumbers : Analyse de numéros de téléphone
- geopy : Géolocalisation
- colorama : Interface colorée
- tqdm : Barres de progression

## Note de sécurité

Cet outil est destiné à un usage éthique et légal uniquement. L'utilisateur est responsable de son utilisation en conformité avec les lois locales et internationales.
