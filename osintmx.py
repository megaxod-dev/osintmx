#!/usr/bin/env python3
import os
import re
import sys
import requests
import phonenumbers
import socket
from time import sleep
from datetime import datetime
from termcolor import colored, cprint
try:
    from pyfiglet import Figlet
except ImportError:
    pass

os.system('clear')

def banner():
    if 'pyfiglet' in sys.modules:
        f = Figlet(font='slant')
        print(colored(f.renderText('OsintMx'), 'red'))
    else:
        title = r"""
  ___  ____ ___ _   _ _____   __  ____  __
 / _ \/ ___|_ _| \ | |_   _| |  \/  \ \/ /
| | | \___ \| ||  \| | | |   | |\/| |\  / 
| |_| |___) | || |\  | | |   | |  | |/  \ 
 \___/|____/___|_| \_| |_|   |_|  |_/_/\_\
        """
        print(colored(title, 'red'))
    print(colored("=" * 55, 'white'))
    print(colored("CREATED BY ", 'white') + colored("Sycka", 'red', attrs=['bold']))
    print(colored("=" * 55, 'white'))

def menu():
    print(colored("\n[1]", 'red') + " Investigation Email")
    print(colored("[2]", 'red') + " Investigation Domaine")
    print(colored("[3]", 'red') + " Investigation IP")
    print(colored("[4]", 'red') + " Investigation Numéro")
    print(colored("[5]", 'red') + " Investigation Pseudo")
    print(colored("[0]", 'red') + " Quitter\n")

def check_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.fullmatch(regex, email)

def email_investigation():
    email = input("\nEntrez l'email: ")
    if not check_email(email):
        cprint("\n[!] Email invalide !", 'red')
        return
    
    cprint(f"\n[+] Analyse de {email}...", 'white')
    
    try:
        # Vérification Hunter.io (version gratuite)
        domain = email.split('@')[1]
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=freekey"
        response = requests.get(url).json()
        
        print(colored("\n=== INFORMATIONS DOMAINE ===", 'red'))
        if 'data' in response:
            print(f"Domaine : {response['data']['domain']}")
            print(f"Organisation : {response['data']['organization']}")
            print(f"Pays : {response['data']['country']}")
            print(f"Emails associés : {len(response['data']['emails'])}")
    except Exception as e:
        cprint(f"\n[!] Erreur API: {e}", 'red')

def domain_investigation():
    domain = input("\nEntrez le domaine: ")
    cprint(f"\n[+] Recherche WHOIS pour {domain}...", 'white')
    
    try:
        url = f"https://api.whoapi.com/?domain={domain}&r=whois&apikey=freekey"
        response = requests.get(url).json()
        
        print(colored("\n=== INFORMATIONS WHOIS ===", 'red'))
        print(f"Créé le : {response['created_date']}")
        print(f"Expire le : {response['expiry_date']}")
        print(f"Registrar : {response['registrar']}")
        print(f"Nameservers : {', '.join(response['nameservers'])}")
    except:
        cprint("\n[!] Impossible de récupérer les informations WHOIS", 'red')

def ip_investigation():
    ip = input("\nEntrez l'adresse IP: ")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        
        print(colored("\n=== GEOLOCALISATION IP ===", 'red'))
        print(f"Pays : {response['country']}")
        print(f"Région : {response['regionName']}")
        print(f"Ville : {response['city']}")
        print(f"Fournisseur : {response['isp']}")
        print(f"Coordonnées : {response['lat']}, {response['lon']}")
    except:
        cprint("\n[!] Impossible de géolocaliser l'IP", 'red')

def phone_investigation():
    number = input("\nEntrez le numéro (avec indicatif): ")
    try:
        parsed = phonenumbers.parse(number, None)
        
        print(colored("\n=== INFO NUMERO ===", 'red'))
        print(f"Pays : {phonenumbers.region_code_for_number(parsed)}")
        print(f"Valide : {phonenumbers.is_valid_number(parsed)}")
        print(f"Type : {phonenumbers.number_type(parsed)}")
        
        from phonenumbers import carrier
        print(f"Opérateur : {carrier.name_for_number(parsed, 'fr')}")
    except:
        cprint("\n[!] Numéro invalide !", 'red')

def username_investigation():
    username = input("\nEntrez le pseudo: ")
    print(colored("\n=== RECHERCHE SOCIALE ===", 'red'))
    
    sites = {
        'Facebook': f'https://facebook.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Github': f'https://github.com/{username}'
    }
    
    for site, url in sites.items():
        try:
            response = requests.head(url)
            print(f"{site}: {'Trouvé' if response.status_code == 200 else 'Non trouvé'}")
        except:
            print(f"{site}: Erreur de connexion")

def main():
    banner()
    while True:
        menu()
        choice = input(colored(">>> ", 'red'))
        
        if choice == '1':
            email_investigation()
        elif choice == '2':
            domain_investigation()
        elif choice == '3':
            ip_investigation()
        elif choice == '4':
            phone_investigation()
        elif choice == '5':
            username_investigation()
        elif choice == '0':
            cprint("\n[+] Au revoir !", 'red')
            sys.exit()
        else:
            cprint("\n[!] Choix invalide !", 'red')
        
        input("\nAppuyez sur Entrée pour continuer...")
        os.system('clear')
        banner()

if __name__ == "__main__":
    main()
