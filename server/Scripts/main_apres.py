import os
import sys
import json
import glob
from getpass import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import tempfile

# Import from new modules
from common_utils import (
    verifier_connexion,
    valider_ip,
    # normalize_text, # Not directly used here, but by compare_sections
    # detect_encoding, # Used by read_file_by_line
    read_file_by_line,
    extract_sections,
    compare_sections,
    display_differences,
    write_differences_to_file,
    nettoyer_fichiers_disque,
    confirmation_box # For cleanup prompts
)
import juniper_data_collector as jdc

# --- Main script logic for APRES ---
connection_apres = None
fichiers_crees_apres = []
APRES_file_path = None # Renamed from APRES
identifiants_data = {} # Store loaded identifiants

try:
    # Trouver et charger le fichier d'identification
    selected_ident_file = None
    if len(sys.argv) > 1:
        selected_ident_file = sys.argv[1]
        if not os.path.exists(selected_ident_file):
            print(f"ERREUR: Fichier d'identifiants spécifié '{selected_ident_file}' introuvable.")
            sys.exit(1)
    else:
        # Fallback: Chercher le fichier identifiants_*.json le plus récent dans le répertoire du script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        list_of_files = glob.glob(os.path.join(script_dir, "identifiants_*.json"))
        if not list_of_files:
            print("ERREUR: Aucun fichier d'identification (identifiants_*.json) trouvé. Exécutez main_avant.py d'abord.")
            sys.exit(1)
        
        if len(list_of_files) > 1:
            print("Plusieurs fichiers d'identification trouvés:")
            for i, file_path_id in enumerate(list_of_files):
                try:
                    # Attempt to read IP and user for better display
                    with open(file_path_id, "r") as f_peek:
                        data_peek = json.load(f_peek)
                    print(f"  {i+1}. {os.path.basename(file_path_id)} (IP: {data_peek.get('ip', 'N/A')}, User: {data_peek.get('username', 'N/A')})")
                except Exception:
                    print(f"  {i+1}. {os.path.basename(file_path_id)} (Impossible de lire les détails)")
            
            while True:
                try:
                    choice_idx = int(input("Choisissez le numéro de la session à utiliser: ")) - 1
                    if 0 <= choice_idx < len(list_of_files):
                        selected_ident_file = list_of_files[choice_idx]
                        break
                    else:
                        print("Choix invalide.")
                except ValueError:
                    print("Veuillez entrer un numéro.")
        else:
            selected_ident_file = list_of_files[0]
        
    print(f"Utilisation du fichier d'identifiants : {selected_ident_file}")
    with open(selected_ident_file, "r", encoding='utf-8') as f_id_load:
        identifiants_data = json.load(f_id_load)

    # Validation des champs requis depuis identifiants_data
    ip_apres = identifiants_data.get("ip")
    username_apres = identifiants_data.get("username")
    # lock_file_path_apres = identifiants_data.get("lock_file_path") # Lock file handled by AVANT
    AVANT_file_from_id = identifiants_data.get("AVANT_file")
    config_file_from_id = identifiants_data.get("config_file_main") # Name from AVANT

    if not all([ip_apres, username_apres, AVANT_file_from_id]):
        raise ValueError("Fichier d'identifiants incomplet ou corrompu (IP, username, AVANT_file manquants).")
    if not valider_ip(ip_apres):
        raise ValueError("Adresse IP invalide dans le fichier d'identifiants.")
    if not os.path.exists(AVANT_file_from_id):
        raise FileNotFoundError(f"Le fichier AVANT '{AVANT_file_from_id}' spécifié dans les identifiants est introuvable.")

    # Boucle pour la connexion SSH (juste pour le mot de passe)
    while True:
        password_apres = getpass(f"Veuillez entrer le mot de passe pour {username_apres}@{ip_apres} : ")
        device_config_apres = {
            'device_type': 'juniper_junos',
            'host': ip_apres,
            'username': username_apres,
            'password': password_apres,
            'timeout': 60,
            'session_log': 'netmiko_session_apres.log', # Separate log for APRES
            'session_log_file_mode': 'append'
        }
        try:
            print(f"\nTentative de connexion à {ip_apres} pour les vérifications APRES...")
            connection_apres = ConnectHandler(**device_config_apres)
            if verifier_connexion(connection_apres):
                print(f"Connecté avec succès au routeur {ip_apres} pour APRES.")
                break
            else:
                print("Échec de la vérification de la connexion APRES. Veuillez réessayer.")
                connection_apres.disconnect() # Cleanly close
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as conn_err_apres:
            print(f"Erreur de connexion Netmiko (APRES) : {str(conn_err_apres)}")
            # Ask to retry password
            if not confirmation_box("Mot de passe incorrect ou problème de connexion. Réessayer?"):
                sys.exit(1) # Exit if user does not want to retry password
        except Exception as e_conn_apres:
            print(f"Échec de la connexion APRES : {str(e_conn_apres)}")
            if not confirmation_box("Voulez-vous réessayer la connexion?"):
                sys.exit(1)

    # Création du fichier temporaire pour APRES
    script_dir_apres = os.path.dirname(os.path.abspath(__file__))
    with tempfile.NamedTemporaryFile(
        mode='w+',
        dir=script_dir_apres,
        prefix='APRES_TEMP_',
        suffix='.txt',
        delete=False,
        encoding='utf-8'
    ) as temp_file_obj_apres:
        fichier_temporaire_apres = temp_file_obj_apres.name
    fichiers_crees_apres.append(fichier_temporaire_apres)

    router_hostname_apres = "inconnu" # Initialize

    # Collect data APRES
    with open(fichier_temporaire_apres, 'w', encoding='utf-8') as file_handle_apres:
        router_hostname_apres, _, _ = jdc.collect_basic_info(connection_apres, file_handle_apres)
        if router_hostname_apres == "":
            raise Exception("Impossible de récupérer le hostname du routeur (APRES). Arrêt.")

        jdc.collect_routing_engine_info(connection_apres, file_handle_apres)
        jdc.collect_interface_info(connection_apres, file_handle_apres)
        jdc.collect_arp_info(connection_apres, file_handle_apres)
        jdc.collect_route_summary(connection_apres, file_handle_apres)
        jdc.collect_ospf_info(connection_apres, file_handle_apres)
        jdc.collect_isis_info(connection_apres, file_handle_apres)
        jdc.collect_mpls_info(connection_apres, file_handle_apres)
        jdc.collect_ldp_info(connection_apres, file_handle_apres)
        jdc.collect_rsvp_info(connection_apres, file_handle_apres)
        jdc.collect_lldp_info(connection_apres, file_handle_apres)
        jdc.collect_lsp_info(connection_apres, file_handle_apres)
        jdc.collect_bgp_info(connection_apres, file_handle_apres)
        jdc.collect_system_services(connection_apres, file_handle_apres)
        jdc.collect_configured_protocols(connection_apres, file_handle_apres)
        jdc.collect_firewall_acls(connection_apres, file_handle_apres)
        jdc.collect_critical_logs(connection_apres, file_handle_apres)
        # Full configuration (APRES version, written to APRES file, no separate config file needed here usually)
        # The original APRES.py writes it to the APRES file only.
        total_config_after = jdc.collect_full_configuration(connection_apres, file_handle_apres, username_apres, router_hostname_apres)


    # Renommer le fichier temporaire APRES
    base_apres_filename = f"APRES_{username_apres}_{router_hostname_apres}.txt"
    APRES_file_path = os.path.join(script_dir_apres, base_apres_filename)
    compteur_apres = 1
    while os.path.exists(APRES_file_path):
        APRES_file_path = os.path.join(script_dir_apres, f"APRES_{username_apres}_{router_hostname_apres}_{compteur_apres}.txt")
        compteur_apres += 1
    
    try:
        os.replace(fichier_temporaire_apres, APRES_file_path)
        print(f"Fichier temporaire APRES renommé en : {APRES_file_path}")
        fichiers_crees_apres.remove(fichier_temporaire_apres)
        fichiers_crees_apres.append(APRES_file_path)
    except Exception as e_rename_apres:
        print(f"Erreur lors du renommage du fichier temporaire APRES : {e_rename_apres}")
        APRES_file_path = fichier_temporaire_apres # Use temp name if rename fails

    # Afficher message de confirmation
    if APRES_file_path and os.path.exists(APRES_file_path):
        print(f"\nLes résultats des vérifications APRES ont été enregistrés dans : {os.path.abspath(APRES_file_path)}.")

    # Comparaison
    print("\n--- Lancement de la comparaison AVANT vs APRES ---")
    content_avant_gen = read_file_by_line(AVANT_file_from_id)
    content_apres_gen = read_file_by_line(APRES_file_path)

    sections_avant_data = extract_sections(content_avant_gen)
    sections_apres_data = extract_sections(content_apres_gen)

    if not sections_avant_data and os.path.exists(AVANT_file_from_id): # File exists but no sections parsed
        print(f"AVERTISSEMENT: Aucune section n'a pu être extraite de {AVANT_file_from_id}. Le fichier est-il vide ou mal formaté?")
    if not sections_apres_data and os.path.exists(APRES_file_path):
        print(f"AVERTISSEMENT: Aucune section n'a pu être extraite de {APRES_file_path}. Le fichier est-il vide ou mal formaté?")

    if not sections_avant_data and not sections_apres_data:
        print("Erreur critique: Impossible d'extraire des sections des fichiers AVANT et APRES. Comparaison impossible.")
    else:
        differences_data = compare_sections(sections_avant_data, sections_apres_data)
        display_differences(differences_data)

        comparaison_filename_base = f"COMPARAISON_{username_apres}_{router_hostname_apres}.txt"
        comparaison_filename = os.path.join(script_dir_apres, comparaison_filename_base)
        compteur_comp = 1
        while os.path.exists(comparaison_filename):
            comparaison_filename = os.path.join(script_dir_apres, f"COMPARAISON_{username_apres}_{router_hostname_apres}_{compteur_comp}.txt")
            compteur_comp += 1
        
        write_differences_to_file(differences_data, comparaison_filename)
        fichiers_crees_apres.append(comparaison_filename) # Track for potential cleanup

    # Suppression du fichier d'identification (selected_ident_file)
    try:
        if selected_ident_file and os.path.exists(selected_ident_file):
            if confirmation_box(f"Voulez-vous supprimer le fichier d'identification utilisé ({os.path.basename(selected_ident_file)})?"):
                os.remove(selected_ident_file)
                print(f"Fichier d'identification '{selected_ident_file}' supprimé.")
            else: # If not deleted, add to a list that won't be auto-cleaned by this script
                pass 
    except Exception as e_del_id:
        print(f"Erreur lors de la suppression du fichier d'identification : {str(e_del_id)}")


except KeyboardInterrupt:
    print("\nOpération interrompue par l'utilisateur (Ctrl+C) dans main_apres.py.")
    sys.exit(1)
except FileNotFoundError as e_fnf:
    print(f"ERREUR Fichier non trouvé (main_apres.py): {e_fnf}")
    sys.exit(1)
except ValueError as e_val:
    print(f"ERREUR de valeur (main_apres.py): {e_val}")
    sys.exit(1)
except Exception as e_main_apres:
    print(f"\nUne erreur majeure s'est produite dans main_apres.py : {str(e_main_apres)}")
    import traceback
    traceback.print_exc()
    if "Socket is closed" in str(e_main_apres) or "Connexion perdue" in str(e_main_apres):
        print("La connexion au routeur semble avoir été interrompue pendant main_apres.py.")
    # Option to relaunch APRES itself (might be complex if state is bad)
    # For now, just exit on major error in APRES.
    sys.exit(1)

finally:
    # Nettoyage final des fichiers générés par APRES
    files_to_potentially_delete = []
    if AVANT_file_from_id and os.path.exists(AVANT_file_from_id):
        files_to_potentially_delete.append(("Fichier AVANT", AVANT_file_from_id))
    if APRES_file_path and os.path.exists(APRES_file_path):
        files_to_potentially_delete.append(("Fichier APRES", APRES_file_path))
    if 'comparaison_filename' in locals() and comparaison_filename and os.path.exists(comparaison_filename):
        files_to_potentially_delete.append(("Fichier COMPARAISON", comparaison_filename))
    if config_file_from_id and os.path.exists(config_file_from_id) and config_file_from_id != "N/A":
        files_to_potentially_delete.append(("Fichier CONFIGURATION (de AVANT)", config_file_from_id))
    
    if files_to_potentially_delete:
        print("\n--- Nettoyage des fichiers ---")
        files_deleted_this_run = []
        for desc, f_path in files_to_potentially_delete:
            del_res = input(f"Voulez-vous supprimer le {desc} ({os.path.basename(f_path)})? (O/N) ").strip().lower()
            if del_res in ['o', 'oui', 'y', 'yes']:
                try:
                    os.remove(f_path)
                    print(f"Fichier {f_path} supprimé.")
                    files_deleted_this_run.append(f_path)
                except Exception as e_del_f:
                    print(f"Erreur lors de la suppression de {f_path}: {e_del_f}")
        
        # Remove deleted files from fichiers_crees_apres if they were there
        if 'comparaison_filename' in locals() and comparaison_filename in files_deleted_this_run:
            if comparaison_filename in fichiers_crees_apres: fichiers_crees_apres.remove(comparaison_filename)
        if APRES_file_path in files_deleted_this_run:
             if APRES_file_path in fichiers_crees_apres: fichiers_crees_apres.remove(APRES_file_path)
    
    # Clean any remaining temp files that might have been missed if script exited early
    # This is mostly for *.tmp files created by this script if something went wrong before rename
    script_dir_final_cleanup = os.path.dirname(os.path.abspath(__file__))
    for temp_pattern in ["APRES_TEMP_*.txt", "AVANT_TEMP_*.txt"]: # From main_avant as well if it crashed
        for f_temp_cleanup in glob.glob(os.path.join(script_dir_final_cleanup, temp_pattern)):
            try:
                if confirmation_box(f"Supprimer le fichier temporaire orphelin {os.path.basename(f_temp_cleanup)}?"):
                    os.remove(f_temp_cleanup)
                    print(f"Fichier temporaire orphelin {f_temp_cleanup} supprimé.")
            except Exception as e_final_temp_del:
                print(f"Erreur suppression temp orphelin {f_temp_cleanup}: {e_final_temp_del}")


    if connection_apres and connection_apres.is_alive():
        print("Déconnexion de la session SSH (APRES)...")
        connection_apres.disconnect()
        print("Session SSH (APRES) déconnectée.")
    elif connection_apres:
        print("La connexion SSH (APRES) semble déjà fermée ou inactive.")

    print("\nFin du script main_apres.py.")