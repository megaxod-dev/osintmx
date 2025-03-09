#!/usr/bin/env python3
import os
import re
import sys
import socket
import dns.resolver
import phonenumbers
import requests
from time import sleep
from datetime import datetime
from termcolor import colored, cprint
import whois

# Configuration DNS globale
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

def banner():
    os.system('clear')
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

# Fonction d'investigation email améliorée
def email_investigation():
    email = input("\nEntrez l'email: ")
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        cprint("\n[!] Format email invalide", 'red')
        return
    
    domain = email.split('@')[1]
    cprint(f"\n[+] Analyse de {email}...", 'white')
    
    try:
        # Vérification MX Records
        cprint("\n=== ENREGISTREMENTS MX ===", 'red')
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print(f"Serveur Mail: {rdata.exchange.to_text()} (Priorité {rdata.preference})")

        # Vérification DNS
        cprint("\n=== VALIDATION DOMAINE ===", 'red')
        try:
            ip = socket.gethostbyname(domain)
            cprint(f"Domaine résolu → IP: {ip}", 'green')
        except socket.gaierror:
            cprint("Domaine inexistant ou non résolu", 'red')
            return

        # Vérification SPF
        cprint("\n=== ENREGISTREMENT SPF ===", 'red')
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                if "v=spf1" in record.to_text():
                    cprint("SPF trouvé: " + record.to_text(), 'green')
                    break
            else:
                cprint("Aucun enregistrement SPF trouvé", 'red')
        except dns.resolver.NoAnswer:
            cprint("Aucun enregistrement SPF trouvé", 'red')

    except dns.resolver.NXDOMAIN:
        cprint("Le domaine n'existe pas", 'red')
    except Exception as e:
        cprint(f"Erreur: {str(e)}", 'red')

# Fonction d'investigation domaine améliorée
def domain_investigation():
    domain = input("\nEntrez le domaine: ").lower().strip()
    
    try:
        cprint("\n=== WHOIS ===", 'red')
        w = whois.whois(domain)
        
        print(f"Créé le: {w.creation_date}")
        print(f"Expire le: {w.expiration_date}")
        print(f"Registrar: {w.registrar}")
        print(f"Name Servers: {', '.join(w.name_servers)}")
        
        # Récupération des enregistrements DNS
        cprint("\n=== ENREGISTREMENTS DNS ===", 'red')
        records = {
            'A': 'Adresses IPv4',
            'AAAA': 'Adresses IPv6',
            'NS': 'Serveurs DNS',
            'MX': 'Serveurs Mail',
            'TXT': 'Enregistrements TXT'
        }
        
        for record, description in records.items():
            try:
                answers = dns.resolver.resolve(domain, record)
                print(f"\n{description}:")
                for answer in answers:
                    print(f"  {answer.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue

        # Vérification ports ouverts
        cprint("\n=== PORTS OUVERTS ===", 'red')
        ports = [21, 22, 25, 53, 80, 443, 3306, 8080]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            status = "OUVERT" if result == 0 else "FERMÉ"
            color = "green" if result == 0 else "red"
            print(colored(f"Port {port}: {status}", color))
            sock.close()
            
    except whois.parser.PywhoisError:
        cprint("Domaine non enregistré", 'red')
    except Exception as e:
        cprint(f"Erreur: {str(e)}", 'red')

def ip_investigation():
    ip = input("\nEntrez l'adresse IP: ").strip()
    
    try:
        # Validation format IP
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            cprint("Format IP invalide", 'red')
            return
            
        cprint("\n=== GEOLOCALISATION ===", 'red')
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        if response['status'] == 'success':
            print(f"Pays: {response['country']}")
            print(f"Ville: {response['city']}")
            print(f"Fournisseur: {response['isp']}")
            print(f"Coordonnées: {response['lat']}, {response['lon']}")
            print(f"Carte: https://maps.google.com/?q={response['lat']},{response['lon']}")
        else:
            cprint("Erreur de géolocalisation", 'red')
            
        # Recherche DNS inversé
        cprint("\n=== DNS INVERSE ===", 'red')
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"Nom d'hôte: {hostname}")
        except socket.herror:
            cprint("Aucun enregistrement PTR trouvé", 'red')
            
    except Exception as e:
        cprint(f"Erreur: {str(e)}", 'red')

def phone_investigation():
    number = input("\nEntrez le numéro (avec indicatif): ").strip()
    
    try:
        parsed = phonenumbers.parse(number, None)
        
        if not phonenumbers.is_valid_number(parsed):
            cprint("Numéro invalide", 'red')
            return
            
        cprint("\n=== INFORMATION NUMÉRO ===", 'red')
        print(f"Pays: {phonenumbers.region_code_for_number(parsed)}")
        print(f"Type: {phonenumbers.number_type(parsed)}")
        print(f"Format international: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        
        from phonenumbers import carrier, timezone
        print(f"Opérateur: {carrier.name_for_number(parsed, 'fr')}")
        print(f"Fuseau horaire: {timezone.time_zones_for_number(parsed)}")
        
    except Exception as e:
        cprint(f"Erreur: {str(e)}", 'red')

def username_investigation():
    username = input("\nEntrez le pseudo: ").strip()
    cprint("\n=== VÉRIFICATION RÉSEAUX SOCIAUX ===", 'red')
    
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'YouTube': f'https://youtube.com/@{username}'
    }
    
    for site, url in sites.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                cprint(f"{site}: Trouvé", 'green')
            else:
                print(f"{site}: Non trouvé")
        except Exception as e:
            print(f"{site}: Erreur de connexion")

def main():
    banner()
    while True:
        menu()
        choice = input(colored(">>> ", 'red'))
        
        actions = {
            '1': email_investigation,
            '2': domain_investigation,
            '3': ip_investigation,
            '4': phone_investigation,
            '5': username_investigation,
            '0': lambda: [cprint("\n[+] Au revoir !", 'red'), sys.exit()]
        }
        
        if choice in actions:
            actions[choice]()
        else:
            cprint("\n[!] Choix invalide !", 'red')
        
        input("\nAppuyez sur Entrée pour continuer...")
        banner()

if __name__ == "__main__":
    main()
