import os
import sys
import json
import time
from pathlib import Path
from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import tempfile
import subprocess

# Import from new modules
from locking_utils import verrouiller_routeur, liberer_verrou_et_fichier
from common_utils import (
    verifier_connexion,
    nettoyer_fichiers_disque,
    confirmation_box,
    valider_ip
)
import juniper_data_collector as jdc
from importlib import import_module

# Dynamically import all public functions from juniper_data_collector
from types import FunctionType
jdc_module = import_module('juniper_data_collector')
jdc_functions = [getattr(jdc_module, name) for name in dir(jdc_module)
                 if isinstance(getattr(jdc_module, name), FunctionType) and not name.startswith('_')]

# List of function names in the desired order
JDC_FUNC_ORDER = [
    'collect_routing_engine_info',
    'collect_interface_info',
    'collect_arp_info',
    'collect_route_summary',
    'collect_ospf_info',
    'collect_isis_info',
    'collect_mpls_info',
    'collect_ldp_info',
    'collect_rsvp_info',
    'collect_lldp_info',
    'collect_lsp_info',
    'collect_bgp_info',
    'collect_system_services',
    'collect_configured_protocols',
    'collect_firewall_acls',
    'collect_critical_logs',
]

def run_all_jdc_collectors(connection, file_handle):
    """Call all jdc data collection functions in the correct order."""
    for func_name in JDC_FUNC_ORDER:
        func = getattr(jdc, func_name, None)
        if callable(func):
            func(connection, file_handle)

# Fonction pour lancer APRES.py (main_apres.py)
def lancer_apres(fichier_identifiants, max_tentatives=3):
    tentatives = 0
    python_exec = sys.executable
    script_apres = os.path.join(os.path.dirname(__file__), "main_apres.py")
    while tentatives < max_tentatives:
        try:
            print(f"\nLancement de main_apres.py")
            result = subprocess.run(
                [python_exec, "main_apres.py", fichier_identifiants],
                check=True,
            )
            return True 
        except subprocess.CalledProcessError as e:
            tentatives += 1
            print(f"Erreur lors de l'exécution (Code {e.returncode}): {e.stderr.strip()}")
            if tentatives < max_tentatives:
                print("Nouvelle tentative...")
            else:
                print("Échec après plusieurs tentatives.")
                return False


# --- Main script logic ---
lock_obj = None # Renamed from 'lock' to avoid conflict with portalocker.Lock
lock_file_path_main = None # Renamed from 'lock_file'
connection = None
fichiers_crees_main = []
AVANT_file = None # Renamed from AVANT
config_file_main = None # Renamed from config_filename
identifiants_file_main = None # Renamed from fichier_identifiants
lancer_apres_flag = False # To control if APRES.py should be launched

try:
    # Boucle pour la connexion SSH
    structured_output_data = {
        "basic_info": {}, "routing_engine": "", "interfaces_up": [], "interfaces_down": [],
        "arp_table": "", "route_summary": "", "ospf_info": "", "isis_info": "", "mpls_info": "",
        "ldp_info": "", "rsvp_info": "", "lldp_info": "", "lsp_info": "", "bgp_summary": "",
        "system_services": [], "configured_protocols": [], "firewall_config": "",
        "critical_logs_messages": "", "critical_logs_chassisd": "", "full_config_set": "",
    }
    while True:
        ip = input("Veuillez entrer l'adresse IP du routeur : ").strip()
        if not valider_ip(ip):
            print("Adresse IP invalide. Veuillez réessayer.")
            continue
        username = input("Veuillez entrer votre nom d'utilisateur : ").strip()
        password = getpass("Veuillez entrer votre mot de passe : ")

        lock_obj, lock_file_path_main = verrouiller_routeur(ip)
        if not lock_obj:
            # verrouiller_routeur already prints message, option to retry or exit
            retry_lock = input("Réessayer d'obtenir le verrou? (oui/non): ").lower()
            if retry_lock not in ['oui', 'o']:
                print("Abandon.")
                sys.exit(1)
            continue # Redemander les informations si verrou échoué et retry

        # Define GENERATED_FILES_DIR before using it
        script_dir = os.path.dirname(os.path.abspath(__file__))
        GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
        Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)

        device_config = {
            'device_type': 'juniper_junos',
            'host': ip,
            'username': username,
            'password': password,
            'timeout': 60,
            'session_log': os.path.join(GENERATED_FILES_DIR, 'netmiko_session_avant.log'),
            'session_log_file_mode': 'append'
        }
        try:
            connection = ConnectHandler(**device_config)
            if verifier_connexion(connection):
                print(f"Connecté avec succès au routeur {ip}")
                break
            else:
                print("Échec de la vérification de la connexion après établissement. Veuillez réessayer.")
                connection.disconnect()
                # Libérer le verrou si la connexion échoue
                liberer_verrou_et_fichier(lock_obj, lock_file_path_main)
                lock_obj, lock_file_path_main = None, None # Reset lock info
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as conn_err:
            print(f"Erreur de connexion Netmiko : {str(conn_err)}")
            liberer_verrou_et_fichier(lock_obj, lock_file_path_main)
            lock_obj, lock_file_path_main = None, None
            # Ask to retry credentials or IP
            if not confirmation_box("Voulez-vous réessayer avec de nouvelles informations?"):
                sys.exit(1)
        except Exception as e:
            print(f"Erreur inattendue lors de la tentative de connexion : {str(e)}")
            liberer_verrou_et_fichier(lock_obj, lock_file_path_main)
            lock_obj, lock_file_path_main = None, None
            if not confirmation_box("Voulez-vous réessayer?"):
                sys.exit(1)
            # continue will restart the loop for IP/user/pass

    # Création du fichier temporaire pour AVANT
    # Ensure temp files are created in the script's directory or a defined output directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    GENERATED_FILES_DIR = os.path.join(script_dir, "generated_files")
    Path(GENERATED_FILES_DIR).mkdir(exist_ok=True, parents=True)
    if not os.access(GENERATED_FILES_DIR, os.W_OK):
        raise PermissionError(f"AVANT CRITIQUE: Pas d'accès en écriture à GENERATED_FILES_DIR ({GENERATED_FILES_DIR})!")
    with tempfile.NamedTemporaryFile(
        mode='w+',
        dir=GENERATED_FILES_DIR, # Create temp file in generated_files
        prefix='AVANT_TEMP_',
        suffix='.txt',
        delete=False,
        encoding='utf-8'
    ) as temp_file_obj:
        fichier_temporaire_avant = temp_file_obj.name
    fichiers_crees_main.append(fichier_temporaire_avant) # Track for cleanup

    router_hostname_main = "inconnu" # Initialize
    
    # Collect data
    with open(fichier_temporaire_avant, 'w', encoding='utf-8') as file_handle_avant:
        # Basic Info (includes hostname needed for filename)
        router_hostname_main, _, _ = jdc.collect_basic_info(connection, file_handle_avant)
        if router_hostname_main == "":
            # This is critical, handle it (jdc.collect_basic_info might raise it too)
            raise Exception("Impossible de récupérer le hostname du routeur. Arrêt.")

        run_all_jdc_collectors(connection, file_handle_avant)
        # Full configuration (writes to AVANT file and creates separate CONFIG file)
        config_file_main = jdc.collect_full_configuration(connection, file_handle_avant, username, router_hostname_main)
        if config_file_main and os.path.exists(config_file_main):
            fichiers_crees_main.append(config_file_main)
        else:
            print("Avertissement: Le fichier de configuration séparé n'a pas été créé ou trouvé.")
            # config_file_main might be None if jdc.collect_full_configuration fails to return it

    # Renommer le fichier temporaire AVANT
    base_avant_filename = f"AVANT_{username}_{router_hostname_main}.txt"
    AVANT_file = os.path.join(GENERATED_FILES_DIR, base_avant_filename) # Place in generated_files
    compteur = 1
    while os.path.exists(AVANT_file):
        AVANT_file = os.path.join(GENERATED_FILES_DIR, f"AVANT_{username}_{router_hostname_main}_{compteur}.txt")
        compteur += 1
    
    try:
        os.replace(fichier_temporaire_avant, AVANT_file)
        print(f"Fichier temporaire renommé en : {AVANT_file}")
        fichiers_crees_main.remove(fichier_temporaire_avant) # No longer temp
        fichiers_crees_main.append(AVANT_file) # Add final AVANT file
    except Exception as e:
        print(f"Erreur lors du renommage du fichier temporaire {fichier_temporaire_avant} en {AVANT_file}: {e}")
        AVANT_file = fichier_temporaire_avant # Use temp name if rename fails (already in fichiers_crees_main)


    # Sauvegarde des identifiants
    identifiants_base_name = f"identifiants_{username}_{router_hostname_main}.json"
    identifiants_file_main = os.path.join(GENERATED_FILES_DIR, identifiants_base_name)
    compteur_id = 1
    while os.path.exists(identifiants_file_main):
        identifiants_file_main = os.path.join(GENERATED_FILES_DIR, f"identifiants_{username}_{router_hostname_main}_{compteur_id}.json")
        compteur_id += 1

    try:
        data_to_save = {
            "ip": ip,
            "username": username,
            # Do not save password
            "lock_file_path": lock_file_path_main, # Path to the lock file
            "AVANT_file": AVANT_file, # Path to AVANT file
            "config_file_main": config_file_main if config_file_main else "N/A" # Path to CONFIG file
        }
        with open(identifiants_file_main, "w", encoding='utf-8') as f_id:
            json.dump(data_to_save, f_id, indent=4)
        fichiers_crees_main.append(identifiants_file_main)
        print(f"Identifiants sauvegardés dans : {identifiants_file_main}")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde des identifiants : {e}")
        # Fallback to .txt if JSON fails (though this is unlikely if basic file I/O works)
        identifiants_file_main_txt = identifiants_file_main.replace(".json", ".txt")
        try:
            with open(identifiants_file_main_txt, "w", encoding='utf-8') as f_txt_id:
                f_txt_id.write("ATTENTION: Fichier non sécurisé (fallback JSON échoué)\n")
                for key, value in data_to_save.items():
                    f_txt_id.write(f"{key}: {value}\n")
            fichiers_crees_main.append(identifiants_file_main_txt)
            identifiants_file_main = identifiants_file_main_txt # Update to the .txt version
            print(f"Identifiants sauvegardés (fallback TXT) dans : {identifiants_file_main}")
        except Exception as e_txt:
            print(f"Échec complet de la sauvegarde des identifiants (même en TXT) : {e_txt}")
            identifiants_file_main = None # Indicate failure

    # Confirmation messages
    try: 
        if not verifier_connexion(connection):
            raise Exception("Connexion perdue avec le routeur")
        file_path_txt = os.path.abspath(AVANT_file)
        print(f"\nToutes les vérifications ont été stockées dans le fichier '{AVANT_file}' à l'emplacement suivant : {file_path_txt}.")
        file_path_json = os.path.abspath(identifiants_file_main)
        print(f"\nLes identifiants de connexion ont été sauvegardés dans le fichier '{identifiants_file_main}' à l'emplacement suivant : {file_path_json} pour référence future.")
        file_path_txt = os.path.abspath(config_file_main)
        print(f"\nConfiguration complète sauvegardée dans le fichier: {config_file_main}")
    except Exception as e:
        print(f"\nErreur lors de l'affichage des chemins des fichiers : {e}")
        raise 

    # MISE À JOUR
    if confirmation_box("Voulez-vous poursuivre la procédure de mise à jour ?"):
        image_file_input = ""
        while True:
            image_file_input = input("Veuillez saisir le nom complet du package logiciel sur le routeur (ex: jinstall-ppc-VERSION-signed.tgz) : ").strip()
            if not image_file_input:
                print("Erreur: Vous devez spécifier un nom de package.")
                continue
            if not image_file_input.endswith('.tgz'):
                if not confirmation_box(f"Attention ! Le package '{image_file_input}' devrait avoir l'extension .tgz. Continuer quand même?"):
                    continue # Ask for filename again
            # Basic format check (can be improved)
            if not ("jinstall" in image_file_input and "signed" in image_file_input):
                 if not confirmation_box(f"Format de fichier '{image_file_input}' inhabituel. Attendu: jinstall-<plateforme>-<VERSION>-signed.tgz. Continuer?"):
                    continue

            # Vérification de la présence du package sur le routeur
            print(f"\nVérification de la présence du package {image_file_input} sur le routeur...")
            try:
                # Check on current master RE's /var/tmp
                # And on other RE's /var/tmp (path from current master is /var/tmp/reX/var/tmp/ for other RE's /var/tmp)
                # Simpler: check /var/tmp/ on *both* REs by invoking command on other RE.
                # Assume image is in /var/tmp/ on *each* RE or /var/tmp on master and will be copied/is accessible.
                # The update process `juniper_update_proc` uses `no-copy`, so file needs to be on target RE's /var/tmp.
                # For now, check standard paths.
                
                # Path on RE0 (current master initially)
                path_re0 = f"/var/tmp/{image_file_input}"
                # Path on RE1 (from RE0's perspective, if RE1 is slot 1)
                path_re1_from_re0 = f"/var/tmp/{image_file_input}" # This assumes the file has same name on RE1's /var/tmp
                                                                # or use command "file list re1:/var/tmp/{image_file_input}"
                
                output_re0_check = connection.send_command(f"file list {path_re0}", read_timeout=20)
                # To check on RE1, if it exists and is backup:
                # output_re1_check = connection.send_command(f"show system snapshot media internal instance 1 | match {image_file_input}") # This is complex
                # Simpler: assume for now that if `request system software add ... no-copy` is used, the user has placed it there.
                # The original script checked /var/tmp/ and /var/tmp/re1/ - this implies /var/tmp/re1 is a synced dir or RE0 can see RE1's /var/tmp that way.
                # More robustly: file list on RE0, then file list on RE1 via `request routing-engine login other...`
                # For this check, let's focus on current master. The update proc will fail if not found on target RE.
                
                print(f"Résultat de 'file list {path_re0}':\n{output_re0_check}")
                file_on_re0 = image_file_input in output_re0_check and "No such file" not in output_re0_check

                # Check on RE1 (backup) - this requires RE1 to be responsive
                output_re1_check = "Non vérifié sur RE1 à ce stade." # Placeholder
                file_on_re1 = False
                try:
                    # Try to list file on other RE if it's a dual-RE system
                    # This command lists content of /var/tmp on the other RE.
                    # Note: `other-routing-engine` might not work if RE1 is down/unreachable.
                    re_status_check = connection.send_command("show chassis routing-engine", read_timeout=10)
                    if "Slot 1" in re_status_check and ("Backup" in re_status_check or "Online" in re_status_check): # Check if RE1 seems up
                        output_re1_check = connection.send_command(f"file list re1:/var/tmp/{image_file_input}", read_timeout=20)
                        print(f"Résultat de 'file list re1:/var/tmp/{image_file_input}':\n{output_re1_check}")
                        file_on_re1 = image_file_input in output_re1_check and "No such file" not in output_re1_check
                    else:
                        print("RE1 non détecté ou pas dans un état permettant la vérification du fichier.")
                        file_on_re1 = True # Skip RE1 check if not clearly up as backup, proceed with caution. User must ensure file is there.


                except Exception as e_re1_check:
                    print(f"Impossible de vérifier le fichier sur RE1 de manière fiable: {e_re1_check}")
                    # Ask user if they are sure file is on RE1's /var/tmp
                    if not confirmation_box(f"Impossible de vérifier {image_file_input} sur RE1. Êtes-vous sûr qu'il est présent sur /var/tmp de RE1?"):
                         continue # Ask for filename again
                    file_on_re1 = True # User confirmed, proceed with caution.

                if not file_on_re0 or not file_on_re1:
                    missing_locations = []
                    if not file_on_re0: missing_locations.append("RE0 (/var/tmp/)")
                    if not file_on_re1 and "Slot 1" in re_status_check : # Only if RE1 was expected to be checked
                        # Check if RE1 was actually checked or skipped
                        if "Non vérifié sur RE1" not in output_re1_check and not ("Backup" in re_status_check or "Online" in re_status_check):
                             pass # RE1 was not in a state to be checked, so don't list as missing
                        else:
                            missing_locations.append("RE1 (/var/tmp/)")


                    print(f"\nLe package {image_file_input} est introuvable sur: {', '.join(missing_locations) if missing_locations else 'une des localisations requises'}.")
                    print("Veuillez vous assurer que le fichier est présent sur /var/tmp/ de chaque Routing Engine.")
                    if confirmation_box("Voulez-vous entrer un nouveau nom de package ou vérifier manuellement?"):
                        continue # Ask for filename again
                    else:
                        print("Interruption de la procédure de mise à jour.")
                        lancer_apres_flag = False # Still run APRES if user aborts here
                        break # Break from image_file_input loop
                
                if not (file_on_re0 and file_on_re1) and ("Slot 1" in re_status_check and ("Backup" in re_status_check or "Online" in re_status_check)):
                    # If dual RE and one is missing, strongly warn.
                    if not confirmation_box(f"AVERTISSEMENT: Fichier manquant sur une des RE. Continuer la mise à jour avec {image_file_input}?"):
                        continue
                elif not confirmation_box(f"Confirmez-vous l'utilisation de {image_file_input} pour la mise à jour?"):
                    continue
                
                # If we got here, image_file_input is set and confirmed. Break from loop.
                break 
            
            except NetmikoTimeoutException:
                print("Timeout lors de la vérification du fichier. Le routeur est peut-être lent.")
                if not confirmation_box("Réessayer la vérification du fichier?"):
                     lancer_apres_flag = False; break
            except Exception as e_file_check:
                print(f"Une erreur est survenue pendant la vérification du package : {str(e_file_check)}")
                if not confirmation_box("Réessayer la vérification du fichier?"):
                    lancer_apres_flag = False; break # Break from image_file_input loop
        
        if not image_file_input and not lancer_apres_flag: # User aborted image selection without error
            print("Procédure de mise à jour annulée par l'utilisateur avant la sélection du fichier.")
            lancer_apres_flag = False
        elif image_file_input: # Proceed with update if image_file_input is set
            try:
                # The perform_junos_update function will handle its own connection state changes.
                # It returns the final active connection object.
                final_connection = perform_junos_update(connection, device_config, image_file_input)
                connection = final_connection # Update main connection object to the one from update proc
                print("\n✓✓✓ Procédure de mise à jour JUNOS terminée avec succès. ✓✓✓")
                lancer_apres_flag = True
            except Exception as e_update:
                print(f"\n❌❌❌ ERREUR CRITIQUE pendant la procédure de mise à jour JUNOS : {str(e_update)} ❌❌❌")
                print("La mise à jour a échoué. Le routeur peut être dans un état instable.")
                print("Il est fortement recommandé de vérifier manuellement l'état du routeur.")
                # Decide if APRES should run. Probably yes, to capture the failed state.
                if confirmation_box("La mise à jour a échoué. Voulez-vous quand même lancer les vérifications APRES?"):
                    lancer_apres_flag = True
                else:
                    lancer_apres_flag = False # User chose not to run APRES
    else:
        print("Procédure de mise à jour non lancée.")
        lancer_apres_flag = True # If update is skipped, still run APRES for before/after comparison of non-updated state


except KeyboardInterrupt:
    print("\nOpération interrompue par l'utilisateur (Ctrl+C).")
    # If interrupted during data collection, AVANT might be incomplete.
    # If identifiants_file_main was created, APRES might still be launchable.
    if identifiants_file_main and os.path.exists(identifiants_file_main):
        if confirmation_box("Interruption. Voulez-vous quand même tenter de lancer les vérifications APRES?"):
            lancer_apres_flag = True
    sys.exit(1) # Exit after finally block
except Exception as e_main:
    print(f"\nUne erreur majeure s'est produite dans main_avant.py : {str(e_main)}")
    import traceback
    traceback.print_exc()
    if "Socket is closed" in str(e_main) or "Connexion perdue" in str(e_main):
        print("La connexion avec le routeur semble avoir été interrompue.")
    
    # Attempt to run APRES if identifiants file exists
    if identifiants_file_main and os.path.exists(identifiants_file_main):
        if confirmation_box("Une erreur est survenue. Voulez-vous quand même tenter de lancer les vérifications APRES?"):
            lancer_apres_flag = True
    else: # Relancer AVANT si pas d'identifiants
        relancer_choix = input("\nVoulez-vous relancer la partie AVANT? (oui/non): ").lower()
        if relancer_choix in ['oui', 'o', 'yes', 'y']:
            python_exec = sys.executable
            script_path = os.path.abspath(__file__)
            # Clean up before relaunch
            nettoyer_fichiers_disque(fichiers_crees_main) # Clean created files
            liberer_verrou_et_fichier(lock_obj, lock_file_path_main) # Release lock
            if connection and connection.is_alive(): connection.disconnect()
            
            print(f"Relance de : {python_exec} {script_path}")
            os.execl(python_exec, python_exec, script_path) # Replaces current process
            sys.exit(0) # Should not be reached if execl works

finally:
    # Lancer APRES.py si nécessaire et si fichier identifiants existe
    if lancer_apres_flag:
        if identifiants_file_main and os.path.exists(identifiants_file_main):
            if confirmation_box("Voulez-vous lancer la partie aprés?"):
                try: 
                    lancer_apres(identifiants_file_main)
                except Exception as e:
                    print(f"Échec critique. Exécutez APRES.py manuellement avec : APRES.py {identifiants_file_main}") 
            else:
                if fichiers_crees_main:
                    nettoyer_fichiers_disque(fichiers_crees_main, lock_obj, lock_file_path_main)
        else:
            print("Fichier d'identifiants non disponible, impossible de lancer la partie APRES automatiquement.")
            nettoyer_fichiers_disque(fichiers_crees_main) # Clean AVANT files
    else: # If not launching APRES for other reasons (e.g. error before identifiants, or user chose not to after error)
        print("La partie APRES ne sera pas lancée. Nettoyage des fichiers de la partie AVANT.")
        nettoyer_fichiers_disque(fichiers_crees_main)

    # Libération du verrou et déconnexion SSH
    liberer_verrou_et_fichier(lock_obj, lock_file_path_main)
    if connection and connection.is_alive(): # Check if connection object exists and is alive
        print("Déconnexion de la session SSH...")
        connection.disconnect()
        print("Session SSH déconnectée.")
    elif connection: # If connection object exists but not alive (e.g. perform_junos_update disconnected it)
        print("La connexion SSH semble déjà fermée ou inactive.")


    print("\nFin du script main_avant.py.")