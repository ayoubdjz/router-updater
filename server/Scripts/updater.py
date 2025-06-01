import os
import sys
import json
import time
import warnings
from pathlib import Path
from getpass import getpass
from netmiko import ConnectHandler
import ipaddress
import tempfile
import portalocker


def run_update_procedure(ip, username, password, image_file, update_logs=None):
    from pathlib import Path
    from netmiko import ConnectHandler
    import sys, time
    # Build device config as in main_avant.py
    device = {
        'device_type': 'juniper_junos',
        'host': ip,
        'username': username,
        'password': password,
        'timeout': 60,
        'session_log': None,  # Optionally add a log file path if needed
        'session_log_file_mode': 'append'
    }
    connection = ConnectHandler(**device)
    #CONFIGURATION INITIALE DE LA MISE À JOUR
    while True:
        # Saisie et validation du nom du package
        # image_file = input("Veuillez saisir le nom complet du package logiciel (format attendu : jinstall-ppc-<VERSION>-signed.tgz) : ").strip()
        if not image_file:
            update_logs.append("Erreur: Vous devez spécifier un nom de package.")
            continue
        prefix = "jinstall-ppc-"
        suffix = "-signed.tgz"
        if prefix not in image_file or suffix not in image_file:
            update_logs.append("Format de fichier incorrect. Attendu: jinstall-ppc-<VERSION>-signed.tgz")
            continue
        # Vérification de la présence du package sur le routeur
        update_logs.append(f"\nVérification de la présence du package {image_file} sur le routeur...")
        try:
            output_re0 = connection.send_command(f"file list re0:/var/tmp/{image_file}")
            output_re1 = connection.send_command(f"file list re1:/var/tmp/{image_file}")
            if "No such file or directory" in output_re0 or "No such file or directory" in output_re1:
                update_logs.append(f"\nLe package {image_file} est introuvable !")
                update_logs.append("Veuillez choisir parmi les alternatives suivantes :")
                update_logs.append("1. Entrer un nouveau nom de package")
                update_logs.append("2. Abandonner la procédure de mise à jour")
                choice = input("Votre choix (1/2): ").strip()
                if choice == '2':
                    update_logs.append("Interruption de la procédure à la demande de l'utilisateur")
                    sys.exit(0)
                continue
            # Confirmation de l'utilisation du package
            confirm = input(f"Confirmez-vous l'utilisation de {image_file} pour la mise à jour? (oui/non): ").lower()
            if confirm not in ['oui']:
                update_logs.append("Saisie non confirmée, veuillez réessayer")
                continue
            break
        except Exception as e:
            update_logs.append(F"\nUne erreur est survenue pendant la vérification : {str(e)}")
            update_logs.append("Veuillez choisir parmi les alternatives suivantes :")
            update_logs.append("1. Recommencer la procédure de mise à jour")
            update_logs.append("2. Abandonner la procédure")
            choice = input("Votre choix (1/2): ").strip()
            if choice == '2':
                update_logs.append("Interruption de la procédure à la demande de l'utilisateur")
                sys.exit(0)
            continue
    # DÉSACTIVATION DES FONCTIONNALITÉS HA 
    update_logs.append("\nDésactivation des fonctionnalités de haute disponibilité...")
    try:
        connection.config_mode()
        commands = [
            "deactivate chassis redundancy",
            "deactivate routing-options nonstop-routing",
            "deactivate system commit synchronize",
            "set system processes clksyncd-service disable"
        ]
        for cmd in commands:
            output = connection.send_command(cmd, read_timeout=30)
            if "error" in output.lower() or "unknown command" in output.lower():
                update_logs.append(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                try: connection.exit_config_mode()
                except: pass
        commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
        commit_output = connection.send_command("commit synchronize", read_timeout=300)
        if "commit complete" not in commit_output.lower(): 
            update_logs.append(f"'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
            try: connection.exit_config_mode()
            except: pass
        connection.exit_config_mode()
        update_logs.append("✓ Configuration de haute disponibilité désactivée avec succès")
    except Exception as e:
        update_logs.append(f"✗ Erreur lors de la désactivation des fonctionnalités HA: {str(e)}")
        raise
    # MISE À JOUR DE RE1
    update_logs.append("\nMise à jour de RE1...")
    try:
        update_logs.append("Établissement de la connexion à RE1...")
        connection.write_channel("request routing-engine login other-routing-engine\n")
        time.sleep(30)
        update_logs.append("✓ Connexion à RE1 établie avec succès")
        update_logs.append("Installation du nouveau logiciel sur RE1...")
        connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
        time.sleep(30)
        # REDÉMARRAGE DE RE1
        update_logs.append("Lancement du redémarrage de RE1...")
        connection.write_channel("request system reboot\n")
        time.sleep(10)
        connection.write_channel("yes\n")
        time.sleep(60)
        update_logs.append("✓ Redémarrage de RE1 initié avec succès")
    except Exception as e:
        update_logs.append(f"✗ Erreur lors de la mise à jour de RE1: {str(e)}")
        raise
    # VÉRIFICATION DU REDÉMARRAGE DE RE1
    update_logs.append("\n Validation du redémarrage de RE1")
    start_time = time.time()
    timeout = 900  # 15 minutes en secondes
    re1_ready = False
    connection.remote_conn.settimeout(15)  # Timeout de lecture plus long
    output_buffer = ""
    try:
        connection.write_channel("show chassis routing-engine |refresh | match Current\n")
        while (time.time() - start_time) < timeout:
            # Lire le flux de sortie
            chunk = connection.read_channel()
            if chunk:
                output_buffer += chunk
                # Afficher en temps réel
                sys.stdout.write(chunk)
                sys.stdout.flush()
                # Vérifier les états attendus
                if "Backup" in output_buffer:
                    re1_ready = True
                    connection.write_channel(chr(3)) 
                    time.sleep(1)
                    connection.clear_buffer()
                    update_logs.append("\n✓ RE1 a terminé son redémarrage.")
                    break
            else:
                time.sleep(1)  # Pause courte si pas de données
        if not re1_ready:
            raise Exception("15 minutes dépassé - RE1 n'a pas restauré son état opérationnel")
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors de la vérification du redémarrage de RE1: {str(e)}")
        connection.write_channel(chr(3))
        time.sleep(1)
        connection.clear_buffer()
        raise
    # VÉRIFICATION DE LA VERSION SUR RE1
    update_logs.append("\nVérification de la version sur RE1...")
    try:
        # Récupérer la version sur RE1
        version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
        # Extraire la version 
        current_version = version_output.split("Junos:")[1].strip()
        # Extraire la version attendue du nom du package 
        prefix = "jinstall-ppc-"
        suffix = "-signed.tgz"
        expected_version = image_file.split(prefix)[1].split(suffix)[0]
        update_logs.append(f"\nVersion actuelle sur RE1: {current_version}")
        update_logs.append(f"Version attendue: {expected_version}")
        if current_version == expected_version:
            update_logs.append("✓ La version sur RE1 correspond à la version attendue")
        else:
            raise Exception(f"ERREUR: La version sur RE1 ({current_version}) ne correspond pas à la version attendue ({expected_version})")
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
        raise
    # BASCULEMENT VERS RE1
    update_logs.append("\nBasculement vers RE1...")
    try:
        # Envoyer la commande de basculement
        switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
        connection.write_channel("yes\n")
        time.sleep(10)
        # Fermer proprement la connexion actuelle
        connection.disconnect()
        # Attendre que le basculement soit effectif (temps estimé)
        update_logs.append("Basculement en cours - attente de 5 minutes...")
        time.sleep(300)
        # Reconnexion au routeur
        update_logs.append("Tentative de reconnexion après basculement...")
        for attempt in range(1, 6):  # 5 tentatives max
            try:
                # Réétablir la connexion directe au routeur
                connection = ConnectHandler(**device)
                # Vérifier le nouvel état
                re_status = connection.send_command("show chassis routing-engine")
                lines = re_status.split('\n')
                slot1_index = None
                for i, line in enumerate(lines):
                    if "Slot 1" in line:
                        slot1_index = i
                        break
                if slot1_index is not None and slot1_index + 1 < len(lines):
                    next_line = lines[slot1_index + 1]
                    if "Current state" in next_line and "Master" in next_line:
                        update_logs.append("✓ Basculement vers RE1 réussi")
                        break
                    else:
                        raise Exception("RE1 n'est pas dans l'état Master")
                else:
                    raise Exception("Slot 1 non trouvé dans la sortie")
            except Exception as e:
                update_logs.append(f"Tentative {attempt}/5 échouée: {str(e)}")
                if attempt < 5:
                    update_logs.append("Nouvelle tentative dans 1 minute...")
                    time.sleep(60)
                else:
                    raise Exception("Échec de reconnexion après basculement")
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors du basculement vers RE1: {str(e)}")
        raise
    # MISE À JOUR DE RE0 
    update_logs.append("\nMise à jour de RE0...")
    try:
        update_logs.append("Établissement de la connexion à RE0...")
        connection.write_channel("request routing-engine login other-routing-engine\n")
        time.sleep(30)
        update_logs.append("✓ Connexion à RE0 établie avec succès")
        update_logs.append("Installation du nouveau logiciel sur RE0...")
        connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
        time.sleep(30)
        update_logs.append("✓ Logiciel installé avec succès sur RE0")
        # REDÉMARRAGE DE RE1
        update_logs.append("Lancement du redémarrage de RE0...")
        connection.write_channel("request system reboot\n")
        time.sleep(10)
        connection.write_channel("yes\n")
        time.sleep(60)
        update_logs.append("✓ Redémarrage de RE0 initié avec succès")
    except Exception as e:
        update_logs.append(f"✗ Erreur lors de la mise à jour de RE0: {str(e)}")
        raise
    # VÉRIFICATION DU REDÉMARRAGE DE RE0 
    update_logs.append("\nValidation du redémarrage de RE0")
    start_time = time.time()
    timeout = 900  # 15 minutes en secondes
    re0_ready = False
    connection.remote_conn.settimeout(15)  # Timeout de lecture plus long
    output_buffer = ""
    try:
        # Envoyer la commande de vérification
        connection.write_channel("show chassis routing-engine |refresh | match Current\n")
        while (time.time() - start_time) < timeout:
            # Lire le flux de sortie
            chunk = connection.read_channel()
            if chunk:
                output_buffer += chunk
                # Afficher en temps réel
                sys.stdout.write(chunk)
                sys.stdout.flush()
                # Vérifier si on a les deux états (Master et Backup)
                if "Backup" in output_buffer:
                    re0_ready = True
                    connection.write_channel(chr(3)) 
                    time.sleep(1)
                    connection.clear_buffer()
                    update_logs.append("\n✓ RE0 a terminé son redémarrage.")
                    break
            else:
                time.sleep(1)  # Pause courte si pas de données
        if not re0_ready:
            raise Exception("15 minutes dépassé - RE0 n'a pas restauré son état opérationnel")   
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors de la vérification du redémarrage de RE0: {str(e)}")
        connection.write_channel(chr(3))
        time.sleep(1)
        connection.clear_buffer()
        raise
    # VÉRIFICATION DE LA VERSION SUR RE0
    update_logs.append("\nVérification de la version sur RE0...")
    try:
        # Récupérer la version sur RE0 (maintenant que RE1 est master)
        version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
        # Extraire la version 
        current_version = version_output.split("Junos:")[1].strip()
        # Extraire la version attendue du nom du package 
        prefix = "jinstall-ppc-"
        suffix = "-signed.tgz"
        expected_version = image_file.split(prefix)[1].split(suffix)[0]
        update_logs.append(f"\nVersion actuelle sur RE0: {current_version}")
        update_logs.append(f"Version attendue: {expected_version}")
        if current_version == expected_version:
            update_logs.append("✓ La version sur RE0 correspond à la version attendue")
        else:
            raise Exception(f"ERREUR: La version sur RE0 ({current_version}) ne correspond pas à la version attendue ({expected_version})")
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
        raise
    # RÉACTIVATION HA 
    update_logs.append("\nRéactivation des fonctionnalités de haute disponibilité...")
    try:
        connection.config_mode()
        commands = [
            "activate chassis redundancy",
            "activate routing-options nonstop-routing",
            "activate system commit synchronize",
            "delete system processes clksyncd-service disable"
        ]
        for cmd in commands:
            output = connection.send_command(cmd, read_timeout=30)
            if "error" in output.lower() or "unknown command" in output.lower():
                update_logs.append(f"UPDATE ERREUR: Commande HA '{cmd}' échouée: {output}")
                try: connection.exit_config_mode()
                except: pass
        commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
        commit_output = connection.send_command("commit synchronize", read_timeout=300)
        if "commit complete" not in commit_output.lower(): 
            update_logs.append(f"'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
            try: connection.exit_config_mode()
            except: pass
        connection.exit_config_mode()
        update_logs.append("✓ Configuration de haute disponibilité activée avec succès")
    except Exception as e:
        update_logs.append(f"✗ Erreur lors de la réactivation des fonctionnalités HA: {str(e)}")
        raise
    # BASCULEMENT FINAL VERS RE0
    update_logs.append("\nRetour à la configuration d'origine : basculement final vers RE0...")
    try:
        # Envoyer la commande de basculement
        switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
        connection.write_channel("yes\n")
        time.sleep(10)
        # Fermer proprement la connexion actuelle
        connection.disconnect()
        # Attendre que le basculement soit effectif (temps estimé)
        update_logs.append("Basculement en cours - attente de 5 minutes...")
        time.sleep(300)
        # Reconnexion au routeur
        update_logs.append("Tentative de reconnexion après basculement final...")
        for attempt in range(1, 6):  # 5 tentatives max
            try:
                # Réétablir la connexion directe au routeur
                connection = ConnectHandler(**device)
                # Vérifier le nouvel état
                re_status = connection.send_command("show chassis routing-engine")
                lines = re_status.split('\n')
                slot1_index = None
                for i, line in enumerate(lines):
                    if "Slot 0" in line:
                        slot1_index = i
                        break
                if slot1_index is not None and slot1_index + 1 < len(lines):
                    next_line = lines[slot1_index + 1]
                    if "Current state" in next_line and "Master" in next_line:
                        update_logs.append("✓ Basculement vers REO réussi")
                        break
                    else:
                        raise Exception("RE0 n'est pas dans l'état Master")
                else:
                    raise Exception("Slot 0 non trouvé dans la sortie")
            except Exception as e:
                update_logs.append(f"Tentative {attempt}/5 échouée: {str(e)}")
                if attempt < 5:
                    update_logs.append("Nouvelle tentative dans 1 minute...")
                    time.sleep(60)
                else:
                    raise Exception("Échec de reconnexion après basculement final")
    except Exception as e:
        update_logs.append(f"\n✗ Erreur lors du basculement final vers RE0: {str(e)}")
        raise
    update_logs.append("✓ Procédure de mise à jour terminée avec succès")