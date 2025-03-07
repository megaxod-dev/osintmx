#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import json
import socket
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier
import requests
from datetime import datetime
import platform
import textwrap
import re
from time import sleep, time
from colorama import init, Fore, Back, Style
import whois

# Initialize colorama with proper Windows settings
init(autoreset=True)

# Set console to UTF-8 mode on Windows
if os.name == 'nt':
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleCP(65001)
    kernel32.SetConsoleOutputCP(65001)

def clear_screen():
    """Clear screen for both Windows and Unix-like systems"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def get_terminal_width():
    """Get terminal width, with fallback for Windows"""
    try:
        if os.name == 'nt':
            from ctypes import windll, create_string_buffer
            h = windll.kernel32.GetStdHandle(-11)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                import struct
                (_, _, _, _, _, left, _, right, _, _, _) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                return right - left + 1
        return os.get_terminal_size().columns
    except:
        return 80  # Fallback width

def center_text(text, width):
    """Center text with proper handling of ANSI color codes"""
    text_length = len(re.sub(r'\x1b\[[0-9;]*m', '', text))
    padding = (width - text_length) // 2
    return ' ' * padding + text + ' ' * (width - text_length - padding)

def wrap_text(text, width, indent=0):
    """Wrap text with proper indentation"""
    indent_str = ' ' * indent
    wrapper = textwrap.TextWrapper(
        width=width - indent,
        initial_indent=indent_str,
        subsequent_indent=indent_str,
        break_long_words=True,
        break_on_hyphens=True
    )
    return wrapper.fill(text)

class OsintMx:
    def __init__(self):
        self.desktop_path = os.path.expanduser("~/Desktop")
        self.project_dir = os.path.join(self.desktop_path, "OsintMx")
        self.results_dir = os.path.join(self.project_dir, "OsintMx_Results")
        
        # Créer le dossier des résultats s'il n'existe pas
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

        # Configuration de colorama
        init(autoreset=True)
        
        # Configuration du résolveur DNS avec des serveurs publics fiables
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Google DNS et Cloudflare
        
        # Headers par défaut pour les requêtes
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        self.headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive'
        }
        
        # Vérifier si on est sous Termux
        self.is_termux = 'com.termux' in os.getenv('PREFIX', '')

    def print(self, message=""):
        """Print a message"""
        print(message)

    def print_success(self, message, indent=0):
        """Print a success message"""
        indent_str = '  ' * indent
        print(f"{indent_str}{Back.GREEN}{Fore.WHITE}[+]{Style.RESET_ALL} {Fore.WHITE}{message}")

    def print_error(self, message, indent=0):
        """Print an error message"""
        indent_str = '  ' * indent
        print(f"{indent_str}{Back.RED}{Fore.WHITE}[!]{Style.RESET_ALL} {Fore.RED}{message}{Style.RESET_ALL}")

    def print_warning(self, message, indent=0):
        """Print a warning message"""
        indent_str = '  ' * indent
        print(f"{indent_str}{Back.YELLOW}{Fore.BLACK}[!]{Style.RESET_ALL} {Fore.YELLOW}{message}{Style.RESET_ALL}")

    def print_info(self, message, indent=0):
        """Print an info message"""
        indent_str = '  ' * indent
        print(f"{indent_str}{Back.BLUE}{Fore.WHITE}[*]{Style.RESET_ALL} {Fore.WHITE}{message}")

    def print_progress(self, message, indent=0):
        """Print a progress message"""
        indent_str = '  ' * indent
        print(f"{indent_str}{Back.RED}{Fore.WHITE}►{Style.RESET_ALL} {Fore.WHITE}{message}")

    def clear_line(self):
        """Efface la ligne courante dans le terminal"""
        sys.stdout.write('\r' + ' ' * get_terminal_width() + '\r')
        sys.stdout.flush()

    def loading_animation(self, duration, message=""):
        """Affiche une animation de chargement pendant la durée spécifiée"""
        chars = ["-", "\\", "|", "/"]  # Simple ASCII animation
        start_time = time()
        i = 0
        try:
            while (time() - start_time) < duration:
                self.clear_line()
                sys.stdout.write(f"{Fore.RED}{chars[i]} {Fore.WHITE}{message}")
                sys.stdout.flush()
                sleep(0.2)
                i = (i + 1) % len(chars)
            self.clear_line()
        except:
            self.clear_line()

    def print_section(self, title):
        """Affiche un titre de section formaté"""
        width = get_terminal_width()
        separator = "-" * width
        print(f"\n{Fore.RED}{separator}")
        print(f"{Fore.WHITE}{title}")
        print(f"{Fore.RED}{separator}\n")

    def check_instagram(self, email):
        """Vérifie si l'email est associé à un compte Instagram"""
        try:
            session = requests.Session()
            headers = self.headers.copy()
            headers.update({
                'Origin': 'https://www.instagram.com',
                'Referer': 'https://www.instagram.com/'
            })

            response = session.get("https://www.instagram.com/accounts/emailsignup/", headers=headers)
            if response.status_code != 200:
                return False

            token = session.cookies.get('csrftoken')
            if not token:
                return False

            headers["x-csrftoken"] = token
            headers["Referer"] = "https://www.instagram.com/accounts/emailsignup/"

            response = session.post(
                "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
                headers=headers,
                data={"email": email}
            )
            
            if response.status_code == 200:
                return "Another account is using the same email." in response.text or "email_is_taken" in response.text
            return False
        except:
            return False

    def check_twitter(self, email):
        """Vérifie si l'email est associé à un compte Twitter"""
        try:
            response = requests.get(
                "https://api.twitter.com/i/users/email_available.json",
                params={"email": email},
                headers=self.headers
            )
            if response.status_code == 200:
                return response.json()["taken"]
            return False
        except:
            return False

    def check_spotify(self, email):
        """Vérifie si l'email est associé à un compte Spotify"""
        try:
            headers = self.headers.copy()
            headers.update({
                'Accept': 'application/json, text/plain, */*'
            })
            
            response = requests.get(
                'https://spclient.wg.spotify.com/signup/public/v1/account',
                headers=headers,
                params={'validate': '1', 'email': email}
            )
            
            if response.status_code == 200:
                return response.json()["status"] == 20
            return False
        except:
            return False

    def check_firefox(self, email):
        """Vérifie si l'email est associé à un compte Firefox"""
        try:
            response = requests.post(
                "https://api.accounts.firefox.com/v1/account/status",
                data={"email": email},
                headers=self.headers
            )
            if response.status_code == 200:
                return "false" not in response.text
            return False
        except:
            return False

    def check_pinterest(self, email):
        """Vérifie si l'email est associé à un compte Pinterest"""
        try:
            response = requests.get(
                "https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/",
                params={
                    "source_url": "/",
                    "data": '{"options": {"email": "' + email + '"}, "context": {}}'
                },
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()["resource_response"]
                if data["message"] == "Invalid email.":
                    return False
                return data["data"] is not False
            return False
        except:
            return False

    def check_imgur(self, email):
        """Vérifie si l'email est associé à un compte Imgur"""
        try:
            session = requests.Session()
            headers = self.headers.copy()
            headers.update({
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://imgur.com',
                'X-Requested-With': 'XMLHttpRequest'
            })

            r = session.get("https://imgur.com/register?redirect=%2Fuser", headers=headers)
            data = {'email': email}
            response = session.post('https://imgur.com/signin/ajax_email_available', headers=headers, data=data)

            if response.status_code == 200:
                data = response.json()['data']
                if data["available"]:
                    return False
                if "Invalid email domain" in response.text:
                    return False
                return True
            return False
        except:
            return False

    def check_social_media(self, email):
        """Vérifie la présence de l'email sur différents réseaux sociaux"""
        self.print_section("Analyse des Réseaux Sociaux")
        results = {"email": email, "found_on": [], "not_found_on": [], "errors": []}
        
        services = {
            "Instagram": self.check_instagram,
            "Twitter": self.check_twitter,
            "Spotify": self.check_spotify,
            "Firefox": self.check_firefox,
            "Pinterest": self.check_pinterest,
            "Imgur": self.check_imgur
        }
        
        found = 0
        not_found = 0
        errors = 0
        
        print()  # Empty line before starting
        
        for service_name, check_function in services.items():
            try:
                self.loading_animation(1.0, f"Vérification de {service_name}")
                if check_function(email):
                    self.print_success(f"[+] {service_name:<15} : Compte trouvé")
                    results["found_on"].append(service_name)
                    found += 1
                else:
                    self.print_info(f"[-] {service_name:<15} : Non trouvé")
                    results["not_found_on"].append(service_name)
                    not_found += 1
            except Exception as e:
                self.print_error(f"[!] {service_name:<15} : Erreur - {str(e)}")
                results["errors"].append(service_name)
                errors += 1
            print()  # Empty line after each result
        
        # Affichage du résumé
        self.print_section("Résumé de l'Analyse")
        
        if found > 0:
            self.print_success("Comptes Détectés:")
            for service in results["found_on"]:
                self.print_info(f"  → {service}")
            print()
        
        self.print_info("Statistiques:")
        self.print_info(f"  → Services analysés : {len(services)}")
        self.print_success(f"  → Comptes trouvés  : {found}")
        self.print_info(f"  → Sans compte      : {not_found}")
        if errors > 0:
            self.print_warning(f"  → Erreurs         : {errors}")
        
        print()  # Empty line for better readability
        return results

    def get_dns_records(self, domain, record_type):
        """Récupère les enregistrements DNS d'un type spécifique"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception as e:
            self.print_warning(f"Erreur lors de la récupération des enregistrements {record_type}: {str(e)}", 1)
            return []

    def domain_info(self, domain):
        self.print_section(f"Analyse du domaine: {domain}")
        results = {"domain": domain, "timestamp": datetime.now().isoformat()}
        
        try:
            self.loading_animation(1, "Analyse du domaine")
            w = whois.whois(domain)
            if w:
                results["whois"] = {}
                
                # Gestion du registrar
                if hasattr(w, 'registrar'):
                    results["whois"]["registrar"] = w.registrar
                    self.print_info("Informations WHOIS")
                    self.print_info(f"Registrar: {w.registrar}", 1)
                
                # Gestion de la date de création
                if hasattr(w, 'creation_date'):
                    if isinstance(w.creation_date, list):
                        results["whois"]["creation_date"] = w.creation_date[0]
                        self.print_info(f"Creation Date: {w.creation_date[0]}", 1)
                    else:
                        results["whois"]["creation_date"] = w.creation_date
                        self.print_info(f"Creation Date: {w.creation_date}", 1)
                
                # Gestion de la date d'expiration
                if hasattr(w, 'expiration_date'):
                    if isinstance(w.expiration_date, list):
                        results["whois"]["expiration_date"] = w.expiration_date[0]
                        self.print_info(f"Expiration Date: {w.expiration_date[0]}", 1)
                    else:
                        results["whois"]["expiration_date"] = w.expiration_date
                        self.print_info(f"Expiration Date: {w.expiration_date}", 1)
                
                # Gestion des serveurs de noms
                if hasattr(w, 'name_servers'):
                    if isinstance(w.name_servers, list):
                        results["whois"]["name_servers"] = w.name_servers
                        self.print_info("Name Servers:", 1)
                        for ns in w.name_servers:
                            self.print_info(f"  → {ns}", 2)
                    elif isinstance(w.name_servers, str):
                        results["whois"]["name_servers"] = [w.name_servers]
                        self.print_info("Name Servers:", 1)
                        self.print_info(f"  → {w.name_servers}", 2)
            
            self.print_progress("\nAnalyse des enregistrements DNS")
            results["dns"] = {}
            
            # Récupération des différents types d'enregistrements
            record_types = {
                'A': 'Enregistrements A',
                'AAAA': 'Enregistrements AAAA',
                'MX': 'Enregistrements MX',
                'NS': 'Enregistrements NS',
                'TXT': 'Enregistrements TXT',
                'CNAME': 'Enregistrements CNAME',
                'SOA': 'Enregistrements SOA'
            }
            
            for record_type, description in record_types.items():
                records = self.get_dns_records(domain, record_type)
                if records:
                    results["dns"][record_type] = records
                    self.print_info(description + ":", 1)
                    for record in records:
                        self.print_info(f"  → {record}", 2)
                                
            self.save_results(domain, results, "domain")
            
        except Exception as e:
            self.print_error(f"Erreur: {str(e)}")

    def phone_info(self, phone_number):
        self.print_section(f"Analyse du numéro: {phone_number}")
        results = {"phone": phone_number, "timestamp": datetime.now().isoformat()}
        
        try:
            self.loading_animation(1, "Analyse du numéro")
            parsed_number = phonenumbers.parse(phone_number)
            
            if not phonenumbers.is_valid_number(parsed_number):
                raise ValueError("Numéro de téléphone invalide")
            
            self.print_progress("Informations de base")
            results["info"] = {
                "valide": True,
                "pays": geocoder.description_for_number(parsed_number, 'fr'),
                "opérateur": carrier.name_for_number(parsed_number, 'fr'),
                "type": "Mobile" if phonenumbers.number_type(parsed_number) == phonenumbers.PhoneNumberType.MOBILE else "Fixe",
                "indicatif": phonenumbers.region_code_for_number(parsed_number),
                "format_international": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "format_national": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
            }
            
            for key, value in results["info"].items():
                self.print_info(f"{key.replace('_', ' ').title()}: {value}", 1)
            
            self.save_results(phone_number, results, "phone")
            
        except phonenumbers.phonenumberutil.NumberParseException:
            self.print_error("Format de numéro invalide. Utilisez le format international (ex: +33612345678)")
        except ValueError as e:
            self.print_error(str(e))
        except Exception as e:
            self.print_error(f"Erreur: {str(e)}")

    def email_info(self, email):
        """Analyse complète d'une adresse email"""
        self.print_section(f"Analyse de l'email: {email}")
        results = {"email": email, "timestamp": datetime.now().isoformat()}
        
        try:
            domain = email.split('@')[1]
            
            # Vérification du domaine
            print()  # Empty line before starting
            self.loading_animation(1.0, "Analyse du domaine")
            
            try:
                mx_records = self.get_dns_records(domain, 'MX')
                results["domain_info"] = {"mx_records": mx_records}
                
                if mx_records:
                    self.print_info("Serveurs de messagerie:")
                    for mx in mx_records:
                        self.print_info(f"  → {mx}")
                    print()
                else:
                    self.print_warning("Aucun serveur de messagerie trouvé")
                    print()
                
                # Vérification des enregistrements de sécurité
                self.loading_animation(1.0, "Analyse des enregistrements de sécurité")
                
                spf_records = self.get_dns_records(domain, 'TXT')
                dmarc_records = self.get_dns_records('_dmarc.' + domain, 'TXT')
                
                results["domain_info"]["spf"] = []
                results["domain_info"]["dmarc"] = []
                
                self.print_info("Enregistrements de sécurité:")
                
                # Analyse SPF
                for record in spf_records:
                    if "v=spf1" in str(record):
                        results["domain_info"]["spf"].append(str(record))
                        self.print_info(f"  → SPF: {record}")
                
                # Analyse DMARC
                for record in dmarc_records:
                    if "v=DMARC1" in str(record):
                        results["domain_info"]["dmarc"].append(str(record))
                        self.print_info(f"  → DMARC: {record}")
                
                print()  # Empty line after security records
                
            except Exception as e:
                self.print_error(f"Erreur lors de l'analyse du domaine: {str(e)}")
                print()
            
            # Recherche sur les réseaux sociaux
            social_results = self.check_social_media(email)
            results.update(social_results)
            
            self.save_results(email, results, "email")
            
        except Exception as e:
            self.print_error(f"Erreur: {str(e)}")
            return None
        
        return results

    def ip_info(self, ip):
        self.print_section(f"Analyse de l'adresse IP: {ip}")
        results = {"ip": ip, "timestamp": datetime.now().isoformat()}
        
        try:
            self.loading_animation(1, "Récupération des informations")
            response = requests.get(f"http://ip-api.com/json/{ip}", headers=self.headers)
            data = response.json()
            
            if data['status'] == 'success':
                self.print_progress("Informations de localisation")
                results["location"] = {
                    "country": data.get('country'),
                    "city": data.get('city'),
                    "region": data.get('regionName'),
                    "isp": data.get('isp'),
                    "org": data.get('org'),
                    "timezone": data.get('timezone'),
                    "latitude": data.get('lat'),
                    "longitude": data.get('lon')
                }
                
                for key, value in results["location"].items():
                    if value:
                        self.print_info(f"{key.replace('_', ' ').title()}: {value}", 1)
                
                try:
                    self.print_progress("\nInformations réseau")
                    hostname = socket.gethostbyaddr(ip)[0]
                    results["network"] = {"hostname": hostname}
                    self.print_info(f"DNS inverse: {hostname}", 1)
                except:
                    results["network"] = {"hostname": None}
                    self.print_warning("Aucun enregistrement DNS inverse trouvé")
            else:
                self.print_error(f"Erreur: {data.get('message', 'Erreur inconnue')}")
                
            self.save_results(ip, results, "ip")
            
        except requests.exceptions.RequestException as e:
            self.print_error(f"Erreur réseau: {str(e)}")
        except Exception as e:
            self.print_error(f"Erreur: {str(e)}")

    def save_results(self, target, data, category):
        """Sauvegarde les résultats dans un fichier JSON"""
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            
        timestamp = datetime.now().strftime("%d%m%y_%H%M%S")
        filename = f"{category}_{timestamp}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            
        file_size = os.path.getsize(filepath)
        if file_size > 1024:
            size_str = f"{file_size/1024:.1f} KB"
        else:
            size_str = f"{file_size} bytes"
        
        self.print_section("Résultats Sauvegardés")
        self.print_success("Analyse terminée avec succès")
        self.print_info(f"  → Fichier : {filename}")
        self.print_info(f"  → Dossier : {self.results_dir}")
        self.print_info(f"  → Format  : JSON ({size_str})")
        print()  # Empty line for better readability

    def print_banner(self):
        """Affiche la bannière de l'application"""
        width = get_terminal_width()
        header_width = min(width, 80)  # Limite la largeur à 80 caractères

        # Bordure supérieure
        print(f"\n{Fore.RED}╔{'═' * (header_width-2)}╗")
        
        # Titre
        print(f"{Fore.RED}║{Back.RED}{Fore.WHITE}{center_text('OSINT MX', header_width-2)}{Style.RESET_ALL}{Fore.RED}║")
        print(f"{Fore.RED}║{Back.RED}{Fore.WHITE}{center_text('Version Professionnelle', header_width-2)}{Style.RESET_ALL}{Fore.RED}║")
        
        # Informations système
        print(f"{Fore.RED}╠{'═' * (header_width-2)}╣")
        system_info = f"Système: {platform.system()} {platform.release()}"
        python_version = f"Python: {platform.python_version()}"
        print(f"{Fore.RED}║{Fore.WHITE}{center_text(system_info, header_width-2)}{Fore.RED}║")
        print(f"{Fore.RED}║{Fore.WHITE}{center_text(python_version, header_width-2)}{Fore.RED}║")
        
        # Pied de page
        print(f"{Fore.RED}╠{'═' * (header_width-2)}╣")
        footer = "Développé avec ♥ pour la communauté OSINT"
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        print(f"{Fore.RED}║{Fore.WHITE}{center_text(footer, header_width-2)}{Fore.RED}║")
        print(f"{Fore.RED}║{Fore.WHITE}{center_text(timestamp, header_width-2)}{Fore.RED}║")
        print(f"{Fore.RED}╚{'═' * (header_width-2)}╝{Style.RESET_ALL}\n")

    def print_help(self):
        width = get_terminal_width()
        header_width = min(width - 4, 80)
        
        self.print(f"\n{Style.BRIGHT}{Fore.WHITE}Options disponibles{Style.RESET_ALL}\n")
        self.print(f"{Fore.WHITE}  -d, --domain  Analyse d'un nom de domaine")
        self.print(f"{Fore.WHITE}  -p, --phone   Analyse d'un numéro de téléphone")
        self.print(f"{Fore.WHITE}  -e, --email   Analyse d'une adresse email")
        self.print(f"{Fore.WHITE}  -i, --ip      Analyse d'une adresse IP")
        self.print(f"\n{Fore.WHITE}Exemple:")
        self.print(f"{Fore.WHITE}  python osintmx.py -d example.com")
        self.print(f"\n{Fore.WHITE}Note: Les résultats sont sauvegardés dans le dossier OsintMx_Results sur le bureau")

def main():
    parser = argparse.ArgumentParser(
        description=f'{Fore.CYAN}OsintMx - Outil professionnel de collecte d\'informations{Style.RESET_ALL}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--domain', help='Domaine à analyser')
    parser.add_argument('-p', '--phone', help='Numéro de téléphone à analyser (avec indicatif pays, ex: +33612345678)')
    parser.add_argument('-e', '--email', help='Adresse email à analyser')
    parser.add_argument('-i', '--ip', help='Adresse IP à analyser')
    
    if len(sys.argv) == 1:
        toolkit = OsintMx()
        toolkit.print_banner()
        toolkit.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    toolkit = OsintMx()
    toolkit.print_banner()
    
    try:
        if args.domain:
            toolkit.domain_info(args.domain)
        if args.phone:
            toolkit.phone_info(args.phone)
        if args.email:
            toolkit.email_info(args.email)
        if args.ip:
            toolkit.ip_info(args.ip)
    except KeyboardInterrupt:
        toolkit.print_error("\nOpération annulée par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        toolkit.print_error(f"\nUne erreur inattendue est survenue: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
