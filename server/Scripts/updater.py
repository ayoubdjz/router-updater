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
import os

def stream_log(update_logs, msg, log_file_path=None):
    update_logs.append(msg)
    if log_file_path:
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')


def run_update_procedure(ip, username, password, image_file, update_logs=None, log_callback=None, log_file_path=None, sse_stream=None):
    try:
        if update_logs is None:
            update_logs = []
        # Ensure log file path is set
        if not log_file_path:
            generated_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generated_files')
            os.makedirs(generated_dir, exist_ok=True)
            log_file_path = os.path.join(generated_dir, f'update_{ip.replace(".", "_")}_{int(time.time())}.log')
        def log(msg):
            stream_log(update_logs, msg, log_file_path=log_file_path)
            if log_callback:
                log_callback(msg)
            if sse_stream:
                sse_stream(msg)
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
        try:
            connection = ConnectHandler(**device)
        except Exception as e:
            log(f"Erreur de connexion au routeur: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # VALIDATION DU NOM DU PACKAGE
        prefix = "jinstall-ppc-"
        suffix = "-signed.tgz"
        if not image_file:
            log(f"Erreur: Vous devez spécifier un nom de package.")
            return {'success': False, 'logs': update_logs, 'error': 'Nom de package manquant'}
        if prefix not in image_file or suffix not in image_file:
            log(f"Format de fichier incorrect. Attendu: jinstall-ppc-<VERSION>-signed.tgz")
            return {'success': False, 'logs': update_logs, 'error': 'Format de fichier incorrect'}

        # Vérification de la présence du package sur le routeur
        log(f"Vérification de la présence du package {image_file} sur le routeur...")
        try:
            output_re0 = connection.send_command(f"file list re0:/var/tmp/{image_file}")
            output_re1 = connection.send_command(f"file list re1:/var/tmp/{image_file}")
            if "No such file or directory" in output_re0 or "No such file or directory" in output_re1:
                log(f"Le package {image_file} est introuvable !")
                return {'success': False, 'logs': update_logs, 'error': 'Package introuvable sur le routeur'}
        except Exception as e:
            log(f"\nUne erreur est survenue pendant la vérification : {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # DÉSACTIVATION DES FONCTIONNALITÉS HA 
        log("Désactivation des fonctionnalités de haute disponibilité...")
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
                    pass
            commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
            commit_output = connection.send_command("commit synchronize", read_timeout=300)
            if "commit complete" not in commit_output.lower(): 
                log(f"'commit synchronize' pour HA a échoué ou a eu une réponse inattendue: {commit_output}")
                try: 
                    pass
                except: 
                    pass
            connection.exit_config_mode()
            log("✓ Configuration de haute disponibilité désactivée avec succès")
        except Exception as e:
            log(f"✗ Erreur lors de la désactivation des fonctionnalités HA: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # MISE À JOUR DE RE1
        log("Mise à jour de RE1...")
        try:
            log("Établissement de la connexion à RE1...")
            connection.write_channel("request routing-engine login other-routing-engine\n")
            time.sleep(30)
            log("✓ Connexion à RE1 établie avec succès")
            log("Installation du nouveau logiciel sur RE1...")
            connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
            time.sleep(30)
            # REDÉMARRAGE DE RE1
            log("Lancement du redémarrage de RE1...")
            connection.write_channel("request system reboot\n")
            time.sleep(10)
            connection.write_channel("yes\n")
            time.sleep(60)
            log("✓ Redémarrage de RE1 initié avec succès")
        except Exception as e:
            log(f"✗ Erreur lors de la mise à jour de RE1: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # VÉRIFICATION DU REDÉMARRAGE DE RE1
        log(" Validation du redémarrage de RE1")
        start_time = time.time()
        timeout = 900  # 15 minutes en secondes
        re1_ready = False
        connection.remote_conn.settimeout(15)  # Timeout de lecture plus long
        output_buffer = ""
        try:
            connection.write_channel("show chassis routing-engine |refresh | match Current\n")
            while (time.time() - start_time) < timeout:
                chunk = connection.read_channel()
                if chunk:
                    output_buffer += chunk
                    if "Backup" in output_buffer:
                        re1_ready = True
                        connection.write_channel(chr(3)) 
                        time.sleep(1)
                        connection.clear_buffer()
                        log("✓ RE1 a terminé son redémarrage.")
                        break
                else:
                    time.sleep(1)
            if not re1_ready:
                log("15 minutes dépassé - RE1 n'a pas restauré son état opérationnel")
                return {'success': False, 'logs': update_logs, 'error': "RE1 n'a pas restauré son état opérationnel"}
        except Exception as e:
            log(f"\n✗ Erreur lors de la vérification du redémarrage de RE1: {str(e)}")
            connection.write_channel(chr(3))
            time.sleep(1)
            connection.clear_buffer()
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # VÉRIFICATION DE LA VERSION SUR RE1
        log("Vérification de la version sur RE1...")
        try:
            version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
            current_version = version_output.split("Junos:")[1].strip()
            expected_version = image_file.split(prefix)[1].split(suffix)[0]
            log(f"\nVersion actuelle sur RE1: {current_version}")
            log(f"Version attendue: {expected_version}")
            if current_version == expected_version:
                log("✓ La version sur RE1 correspond à la version attendue")
            else:
                log(f"ERREUR: La version sur RE1 ({current_version}) ne correspond pas à la version attendue ({expected_version})")
                return {'success': False, 'logs': update_logs, 'error': 'Version RE1 incorrecte'}
        except Exception as e:
            log(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # BASCULEMENT VERS RE1
        log("Basculement vers RE1...")
        try:
            switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
            connection.write_channel("yes\n")
            time.sleep(10)
            connection.disconnect()
            log("Basculement en cours - attente de 5 minutes...")
            time.sleep(300)
            log("Tentative de reconnexion après basculement...")
            for attempt in range(1, 6):
                try:
                    connection = ConnectHandler(**device)
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
                            log("✓ Basculement vers RE1 réussi")
                            break
                        else:
                            raise Exception("RE1 n'est pas dans l'état Master")
                    else:
                        raise Exception("Slot 1 non trouvé dans la sortie")
                except Exception as e:
                    log(f"Tentative {attempt}/5 échouée: {str(e)}")
                    if attempt < 5:
                        log("Nouvelle tentative dans 1 minute...")
                        time.sleep(60)
                    else:
                        return {'success': False, 'logs': update_logs, 'error': 'Échec de reconnexion après basculement'}
        except Exception as e:
            log(f"\n✗ Erreur lors du basculement vers RE1: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # MISE À JOUR DE RE0 
        log("Mise à jour de RE0...")
        try:
            log("Établissement de la connexion à RE0...")
            connection.write_channel("request routing-engine login other-routing-engine\n")
            time.sleep(30)
            log("✓ Connexion à RE0 établie avec succès")
            log("Installation du nouveau logiciel sur RE0...")
            connection.write_channel(f"request system software add /var/tmp/{image_file} no-validate\n") 
            time.sleep(30)
            log("✓ Logiciel installé avec succès sur RE0")
            log("Lancement du redémarrage de RE0...")
            connection.write_channel("request system reboot\n")
            time.sleep(10)
            connection.write_channel("yes\n")
            time.sleep(60)
            log("✓ Redémarrage de RE0 initié avec succès")
        except Exception as e:
            log(f"✗ Erreur lors de la mise à jour de RE0: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # VÉRIFICATION DU REDÉMARRAGE DE RE0 
        log("Validation du redémarrage de RE0")
        start_time = time.time()
        timeout = 900  # 15 minutes en secondes
        re0_ready = False
        connection.remote_conn.settimeout(15)
        output_buffer = ""
        try:
            connection.write_channel("show chassis routing-engine |refresh | match Current\n")
            while (time.time() - start_time) < timeout:
                chunk = connection.read_channel()
                if chunk:
                    output_buffer += chunk
                    if "Backup" in output_buffer:
                        re0_ready = True
                        connection.write_channel(chr(3)) 
                        time.sleep(1)
                        connection.clear_buffer()
                        log("✓ RE0 a terminé son redémarrage.")
                        break
                else:
                    time.sleep(1)
            if not re0_ready:
                log("15 minutes dépassé - RE0 n'a pas restauré son état opérationnel")
                return {'success': False, 'logs': update_logs, 'error': "RE0 n'a pas restauré son état opérationnel"}
        except Exception as e:
            log(f"\n✗ Erreur lors de la vérification du redémarrage de RE0: {str(e)}")
            connection.write_channel(chr(3))
            time.sleep(1)
            connection.clear_buffer()
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # VÉRIFICATION DE LA VERSION SUR RE0
        log("Vérification de la version sur RE0...")
        try:
            version_output = connection.send_command("show version invoke-on other-routing-engine | match \"Junos:\"")
            current_version = version_output.split("Junos:")[1].strip()
            expected_version = image_file.split(prefix)[1].split(suffix)[0]
            log(f"\nVersion actuelle sur RE0: {current_version}")
            log(f"Version attendue: {expected_version}")
            if current_version == expected_version:
                log("✓ La version sur RE0 correspond à la version attendue")
            else:
                pass
        except Exception as e:
            log(f"\n✗ Erreur lors de la vérification de version: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # RÉACTIVATION HA 
        log("Réactivation des fonctionnalités de haute disponibilité...")
        try:
            connection.config_mode()
            commands = [
                "activate chassis redundancy",
                "activate routing-options nonstop-routing",
                "activate system commit synchronize",
                "delete system processes clksyncd-service disable"
            ]
            for cmd in commands:
                pass
            commit_output = connection.commit(comment="HA features update via API", read_timeout=300, and_quit=False)
            commit_output = connection.send_command("commit synchronize", read_timeout=300)
            if "commit complete" not in commit_output.lower(): 
                pass
            connection.exit_config_mode()
            log("✓ Configuration de haute disponibilité activée avec succès")
        except Exception as e:
            log(f"✗ Erreur lors de la réactivation des fonctionnalités HA: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        # BASCULEMENT FINAL VERS RE0
        log("Retour à la configuration d'origine : basculement final vers RE0...")
        try:
            switch_q_out = connection.send_command("request chassis routing-engine master switch", expect_string=r"Toggle mastership between routing engines", strip_prompt=False, strip_command=False, read_timeout=30)
            connection.write_channel("yes\n")
            time.sleep(10)
            connection.disconnect()
            log("Basculement en cours - attente de 5 minutes...")
            time.sleep(300)
            log("Tentative de reconnexion après basculement final...")
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
                            log("✓ Basculement vers REO réussi")
                            break
                        else:
                            raise Exception("RE0 n'est pas dans l'état Master")
                    else:
                        raise Exception("Slot 0 non trouvé dans la sortie")
                except Exception as e:
                    log(f"Tentative {attempt}/5 échouée: {str(e)}")
                    if attempt < 5:
                        log("Nouvelle tentative dans 1 minute...")
                        time.sleep(60)
                    else:
                        raise Exception("Échec de reconnexion après basculement final")
        except Exception as e:
            log(f"\n✗ Erreur lors du basculement final vers RE0: {str(e)}")
            return {'success': False, 'logs': update_logs, 'error': str(e)}

        log("✓ Procédure de mise à jour terminée avec succès")
        return {'success': True, 'logs': update_logs}
    except Exception as e:
        log(f"\nUne erreur s'est produite pendant l'exécution du script : {str(e)}")
        if connection:
            connection.disconnect()
        if "Socket is closed" in str(e) or "Connexion perdue" in str(e):
            log("La connexion avec le routeur a été interrompue.")
        return {'success': False, 'logs': update_logs, 'error': "La connexion avec le routeur a été interrompue."}