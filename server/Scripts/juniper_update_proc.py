import time
import sys
from netmiko import ConnectHandler # For reconnections
# from common_utils import verifier_connexion # If needed for checks within the update

def perform_junos_update(initial_connection, device_config, image_file_name):
    # This function will manage its own connection object after the initial one is passed.
    # It's crucial because of reboots and mastership switches.
    # The 'initial_connection' might become stale.
    current_connection = initial_connection 

    print(f"\n--- Début de la procédure de mise à jour avec {image_file_name} ---")

    # CONFIGURATION INITIALE DE LA MISE À JOUR (Validation du package - déjà done in main_avant.py)
    # The main_avant.py should handle the input and validation of image_file_name.
    # Here we assume image_file_name is validated and present.

    # DÉSACTIVATION DES FONCTIONNALITÉS HA
    print("\n1. Désactivation des fonctionnalités de haute disponibilité...")
    try:
        current_connection.config_mode()
        commands_deactivate_ha = [
            "deactivate chassis redundancy graceful-switchover", # More specific
            "deactivate routing-options nonstop-routing",
            "deactivate system commit synchronize",
            # "set system processes clksyncd-service disable" # This might not be standard or necessary for all updates
        ]
        for cmd in commands_deactivate_ha:
            print(f"Exécution: {cmd}")
            current_connection.send_command_timing(cmd)
        
        print("Application de la désactivation HA (commit synchronize)...")
        # commit_output = current_connection.commit(comment="Deactivate HA for upgrade", and_quit=False, confirm_timeout=300)
        # Using write_channel for commit synchronize to handle potential prompts or long waits
        current_connection.write_channel("commit synchronize\n")
        time.sleep(5) # Give it a moment to start
        # Look for commit complete or prompt
        commit_output = current_connection.read_until_prompt(read_timeout=300) # 5 min timeout for commit sync
        print(commit_output)
        if "commit complete" not in commit_output.lower() and "commit confirmed" not in commit_output.lower():
            # If it's stuck on a prompt from the other RE, it might be an issue.
            # For now, assume it completes or times out.
            if "error" in commit_output.lower():
                 raise Exception(f"Erreur lors du commit de désactivation HA: {commit_output}")
            print("Avertissement: 'commit complete' non détecté clairement après désactivation HA.")

        current_connection.exit_config_mode()
        print("✓ Configuration de haute disponibilité désactivée (ou tentative effectuée).")
    except Exception as e:
        print(f"Erreur lors de la désactivation HA : {str(e)}")
        try: current_connection.exit_config_mode() # Ensure exit config mode
        except: pass
        raise # Critical step

    # MISE À JOUR DE RE1 (Backup RE)
    print("\n2. Mise à jour de RE1 (Backup)...")
    try:
        print("Établissement de la connexion CLI vers RE1...")
        # Ensure we are not in config mode before this command
        current_connection.send_command_timing("request routing-engine login other-routing-engine", strip_prompt=False, strip_command=False)
        # Wait for prompt from other RE (e.g., user@re1>")
        time.sleep(5) # Let the command propagate
        re1_prompt_output = current_connection.read_until_pattern(r'(%|>|#)\s*$') # Wait for a generic prompt
        print(f"Connecté à RE1 (sortie: {re1_prompt_output.strip()})")

        print(f"Installation du nouveau logiciel {image_file_name} sur RE1...")
        # Using send_command_timing for long-running commands
        # Adding no-copy based on typical Junos upgrade best practices if image is already there
        # The original command was "request system software add /var/tmp/{image_file} no-validate"
        # If dual-RE, image should be on both /var/tmp or use 'no-copy' if supported and REs sync /var/tmp
        # For safety, let's assume the image needs to be specified on the target RE's path
        # The path /var/tmp/ is usually specific to the RE you're on.
        # If `image_file_name` refers to `/var/tmp/file.tgz`, it's on current master (RE0).
        # For RE1, it should be on RE1's `/var/tmp`. Path might need to be `/var/tmp/re1/{image_file}` from RE0 perspective
        # Or, if already on RE1's /var/tmp, then just `/var/tmp/{image_file}` when logged into RE1.
        # The original script checked `/var/tmp/re1/{image_file}` from RE0, implying it was copied there.
        # So, when on RE1, the path is just `/var/tmp/{image_file_name}`
        
        install_cmd_re1 = f"request system software add /var/tmp/{image_file_name} no-validate no-copy"
        print(f"Commande d'installation RE1: {install_cmd_re1}")
        # Increased delay_factor significantly for software add, which can take many minutes.
        # read_timeout in send_command should be high.
        # Using send_command for simplicity, Netmiko handles prompt detection.
        install_output_re1 = current_connection.send_command(
            install_cmd_re1,
            expect_string=r'reboot', # Expecting something related to reboot prompt or completion
            strip_prompt=False, 
            strip_command=False,
            read_timeout=1800 # 30 minutes for software add
        )
        print(f"Sortie de l'installation sur RE1:\n{install_output_re1}")
        if "error" in install_output_re1.lower() or "fail" in install_output_re1.lower():
            # Go back to RE0 CLI before raising
            current_connection.send_command_timing("exit", strip_prompt=False, strip_command=False) # Exit from RE1 CLI
            current_connection.read_until_prompt() # Wait for RE0 prompt
            raise Exception(f"Échec de l'installation sur RE1: {install_output_re1}")
        print("✓ Installation sur RE1 terminée.")

        # REDÉMARRAGE DE RE1
        print("Lancement du redémarrage de RE1...")
        # Send reboot from RE1's console
        current_connection.send_command("request system reboot", expect_string=r"Reboot the system.*yes,no", strip_prompt=False, read_timeout=30)
        current_connection.send_command("yes", expect_string=r"Shutdown NOW|going down immediately", strip_prompt=False, read_timeout=30) # Adjusted expect_string
        print("Commande de redémarrage de RE1 envoyée.")
        # After reboot command, connection to RE1 will be lost. We are still on RE0's console controlling RE1.
        # We need to exit from the 'request routing-engine login other-routing-engine' session back to RE0.
        # This usually happens automatically when the other RE disconnects/reboots.
        # Wait for the prompt of the master RE (RE0).
        print("Attente du retour au prompt de RE0...")
        # The connection object is still tied to RE0's perspective.
        # After RE1 reboots, the `rcli` session to it should terminate.
        time.sleep(10) # Give time for RE1 to start shutdown
        # Try to read until RE0 prompt.
        current_connection.read_until_prompt(read_timeout=60) # Should return to RE0's prompt
        print("Retourné au prompt de RE0.")

    except Exception as e:
        print(f"Erreur lors de la mise à jour ou redémarrage de RE1 : {str(e)}")
        # Try to exit RE1 cli if still there
        try:
            current_connection.send_command_timing("exit", strip_prompt=False, strip_command=False)
            current_connection.read_until_prompt()
        except: pass
        raise

    # VÉRIFICATION DU REDÉMARRAGE DE RE1
    print("\n3. Validation du redémarrage de RE1 (depuis RE0)...")
    start_time_re1_reboot = time.time()
    timeout_re1_reboot = 900  # 15 minutes
    re1_ready = False
    try:
        while (time.time() - start_time_re1_reboot) < timeout_re1_reboot:
            print(f"Attente de RE1... ({int(time.time() - start_time_re1_reboot)}s / {timeout_re1_reboot}s)")
            # Command is run on RE0 to check status of RE1
            chassis_output = current_connection.send_command("show chassis routing-engine", read_timeout=20)
            re1_status_found = False
            re1_is_backup = False
            lines = chassis_output.splitlines()
            for i, line in enumerate(lines):
                if "Routing Engine status:" in line: continue # Header
                if "Slot 1" in line: # Assuming RE1 is Slot 1
                    re1_status_found = True
                    # Check next few lines for state
                    for j in range(i + 1, min(i + 5, len(lines))):
                        if "State" in lines[j] and "Backup" in lines[j]:
                             # Could also be "Present" if it's just up but GRES not synced
                             # "Online" is also a good sign after reboot
                            if "Online" in lines[j] or "Backup" in lines[j]:
                                re1_is_backup = True
                                break
                    break # Found Slot 1 block
            
            if re1_status_found and re1_is_backup:
                print("\n✓ RE1 est revenu en mode Backup/Online.")
                re1_ready = True
                break
            
            # Check for specific error states if possible
            if re1_status_found and not re1_is_backup:
                print(f"RE1 trouvé, mais pas encore Backup. Statut actuel (extrait):\n{chassis_output}")

            time.sleep(30)  # Wait before re-checking
            
        if not re1_ready:
            raise Exception(f"Timeout ({timeout_re1_reboot // 60} min) - RE1 n'a pas restauré son état Backup/Online.")
        print("✓ RE1 a terminé son redémarrage.")

        # VÉRIFICATION DE LA VERSION SUR RE1
        print("\nVérification de la version sur RE1...")
        version_output_re1 = current_connection.send_command("show version invoke-on other-routing-engine | match Junos:", read_timeout=30)
        current_version_re1 = "inconnue"
        if "Junos:" in version_output_re1:
            current_version_re1 = version_output_re1.split("Junos:")[1].strip().split()[0] # Get first word after Junos:

        # Extract expected version from image_file_name (e.g., jinstall-ppc-15.1R7.8-signed.tgz -> 15.1R7.8)
        # This logic depends heavily on the filename format.
        expected_version_parts = image_file_name.split("jinstall-")[1 if "jinstall-" in image_file_name else 0:]
        if expected_version_parts:
            expected_version_parts = expected_version_parts[0].split("-signed.tgz")[0].split("-domestic.tgz")[0].split(".tgz")[0]
            # Remove "ppc-", "ex-", "mx-" etc. if they are part of version string in filename
            prefixes_to_remove = ["ppc-", "ex-", "srx-", "mx-", "vmhost-"]
            for pfx in prefixes_to_remove:
                if expected_version_parts.startswith(pfx):
                    expected_version_parts = expected_version_parts[len(pfx):]
            expected_version = expected_version_parts
        else:
            expected_version = "ERREUR_PARSING_NOM_IMAGE"

        print(f"Version actuelle sur RE1: {current_version_re1}")
        print(f"Version attendue (depuis nom fichier): {expected_version}")
        
        # Version comparison needs to be somewhat flexible (e.g. 15.1R7 vs 15.1R7-S1)
        if expected_version in current_version_re1: # Check if expected is substring of current
            print("✓ La version sur RE1 correspond à la version attendue.")
        else:
            raise Exception(f"ERREUR: La version sur RE1 ({current_version_re1}) ne correspond pas à la version attendue ({expected_version}).")

    except Exception as e:
        print(f"Erreur lors de la validation/vérification de RE1 post-redémarrage : {str(e)}")
        raise


    # BASCULEMENT VERS RE1 (pour que RE1 devienne Master)
    print("\n4. Basculement vers RE1 (pour qu'il devienne Master)...")
    try:
        print("Envoi de la commande de basculement...")
        # Command is run on current master (RE0)
        switch_output = current_connection.send_command_timing(
            "request chassis routing-engine master switch",
            strip_prompt=False, strip_command=False
        ) # Expect a confirmation
        print(f"Sortie de la demande de basculement:\n{switch_output}")
        
        if "Toggle mastership" in switch_output or "yes,no" in switch_output: # Check for confirmation prompt
            current_connection.write_channel("yes\n")
            print("Confirmation 'yes' envoyée pour le basculement.")
            # Read until connection drops or a message indicating switchover
            # The current connection (to RE0) will likely drop.
            time.sleep(10) # Allow switch to initiate
            print("Attente de la perte de connexion à l'ancien master (RE0)...")
            try:
                # This read might timeout or raise an error if connection drops, which is expected.
                current_connection.read_until_prompt(read_timeout=60) 
            except Exception as conn_drop_ex:
                print(f"Connexion à l'ancien master perdue comme attendu: {conn_drop_ex}")
        else:
            print("AVERTISSEMENT: Confirmation de basculement non détectée. Tentative de continuer...")

        print("Déconnexion de la session actuelle (vers RE0)...")
        current_connection.disconnect() # Disconnect from RE0

        print("Attente du basculement effectif (environ 5 minutes)...")
        time.sleep(300) # 5 minutes for switchover and RE1 to stabilize as master

        print("Tentative de reconnexion au routeur (devrait être RE1 maintenant Master)...")
        reconnected_to_new_master = False
        for attempt in range(1, 6):
            print(f"Tentative de reconnexion {attempt}/5...")
            try:
                current_connection = ConnectHandler(**device_config) # Reconnect using original device params
                if not current_connection.is_alive():
                    raise Exception("Connexion échouée (is_alive=False)")
                
                # Verify RE1 is now master
                re_status_output = current_connection.send_command("show chassis routing-engine", read_timeout=30)
                lines_re_status = re_status_output.splitlines()
                re1_is_master_check = False
                for i, line in enumerate(lines_re_status):
                    if "Slot 1" in line: # RE1
                        for j in range(i + 1, min(i + 5, len(lines_re_status))):
                            if "State" in lines_re_status[j] and "Master" in lines_re_status[j]:
                                re1_is_master_check = True
                                break
                        break
                if re1_is_master_check:
                    print("✓ Reconnexion réussie. RE1 est maintenant Master.")
                    reconnected_to_new_master = True
                    break
                else:
                    print(f"RE1 n'est pas Master. Statut:\n{re_status_output}")
                    current_connection.disconnect() # Disconnect if not correct state
                    if attempt < 5: time.sleep(60)
            except Exception as reconn_e:
                print(f"Échec de la tentative de reconnexion {attempt}: {str(reconn_e)}")
                if attempt < 5:
                    print("Nouvelle tentative dans 1 minute...")
                    time.sleep(60)
        
        if not reconnected_to_new_master:
            raise Exception("Échec de reconnexion au routeur après basculement vers RE1 ou RE1 non Master.")
            
    except Exception as e:
        print(f"Erreur lors du basculement vers RE1 : {str(e)}")
        raise

    # MISE À JOUR DE RE0 (maintenant Backup)
    # current_connection is now to RE1 (Master)
    print("\n5. Mise à jour de RE0 (maintenant Backup)...")
    try:
        print("Établissement de la connexion CLI vers RE0 (depuis RE1)...")
        current_connection.send_command_timing("request routing-engine login other-routing-engine", strip_prompt=False, strip_command=False)
        time.sleep(5)
        re0_prompt_output = current_connection.read_until_pattern(r'(%|>|#)\s*$')
        print(f"Connecté à RE0 (sortie: {re0_prompt_output.strip()})")

        print(f"Installation du nouveau logiciel {image_file_name} sur RE0...")
        install_cmd_re0 = f"request system software add /var/tmp/{image_file_name} no-validate no-copy"
        print(f"Commande d'installation RE0: {install_cmd_re0}")
        install_output_re0 = current_connection.send_command(
            install_cmd_re0,
            expect_string=r'reboot', 
            strip_prompt=False, 
            strip_command=False,
            read_timeout=1800 # 30 minutes
        )
        print(f"Sortie de l'installation sur RE0:\n{install_output_re0}")
        if "error" in install_output_re0.lower() or "fail" in install_output_re0.lower():
            current_connection.send_command_timing("exit", strip_prompt=False, strip_command=False) # Exit from RE0 CLI
            current_connection.read_until_prompt() # Wait for RE1 prompt
            raise Exception(f"Échec de l'installation sur RE0: {install_output_re0}")
        print("✓ Installation sur RE0 terminée.")

        # REDÉMARRAGE DE RE0
        print("Lancement du redémarrage de RE0...")
        current_connection.send_command("request system reboot", expect_string=r"Reboot the system.*yes,no", strip_prompt=False, read_timeout=30)
        current_connection.send_command("yes", expect_string=r"Shutdown NOW|going down immediately", strip_prompt=False, read_timeout=30)
        print("Commande de redémarrage de RE0 envoyée.")
        
        print("Attente du retour au prompt de RE1...")
        time.sleep(10)
        current_connection.read_until_prompt(read_timeout=60) # Should return to RE1's prompt
        print("Retourné au prompt de RE1.")

    except Exception as e:
        print(f"Erreur lors de la mise à jour ou redémarrage de RE0 : {str(e)}")
        try: # Try to exit RE0 cli if still there
            current_connection.send_command_timing("exit", strip_prompt=False, strip_command=False)
            current_connection.read_until_prompt()
        except: pass
        raise

    # VÉRIFICATION DU REDÉMARRAGE DE RE0
    # current_connection is to RE1 (Master)
    print("\n6. Validation du redémarrage de RE0 (depuis RE1)...")
    start_time_re0_reboot = time.time()
    timeout_re0_reboot = 900  # 15 minutes
    re0_ready_as_backup = False
    try:
        while (time.time() - start_time_re0_reboot) < timeout_re0_reboot:
            print(f"Attente de RE0... ({int(time.time() - start_time_re0_reboot)}s / {timeout_re0_reboot}s)")
            chassis_output_re0_check = current_connection.send_command("show chassis routing-engine", read_timeout=20)
            re0_status_found_check = False
            re0_is_backup_check = False
            lines_re0_check = chassis_output_re0_check.splitlines()
            for i, line in enumerate(lines_re0_check):
                if "Slot 0" in line: # RE0
                    re0_status_found_check = True
                    for j in range(i + 1, min(i + 5, len(lines_re0_check))):
                        if "State" in lines_re0_check[j] and ("Backup" in lines_re0_check[j] or "Online" in lines_re0_check[j]):
                            re0_is_backup_check = True
                            break
                    break
            
            if re0_status_found_check and re0_is_backup_check:
                print("\n✓ RE0 est revenu en mode Backup/Online.")
                re0_ready_as_backup = True
                break
            
            if re0_status_found_check and not re0_is_backup_check:
                 print(f"RE0 trouvé, mais pas encore Backup. Statut actuel (extrait):\n{chassis_output_re0_check}")

            time.sleep(30)
            
        if not re0_ready_as_backup:
            raise Exception(f"Timeout ({timeout_re0_reboot // 60} min) - RE0 n'a pas restauré son état Backup/Online.")
        print("✓ RE0 a terminé son redémarrage et est Backup.")

        # VÉRIFICATION DE LA VERSION SUR RE0
        print("\nVérification de la version sur RE0...")
        version_output_re0 = current_connection.send_command("show version invoke-on other-routing-engine | match Junos:", read_timeout=30)
        current_version_re0 = "inconnue"
        if "Junos:" in version_output_re0:
            current_version_re0 = version_output_re0.split("Junos:")[1].strip().split()[0]
        
        # expected_version was parsed earlier
        print(f"Version actuelle sur RE0: {current_version_re0}")
        print(f"Version attendue: {expected_version}") # Re-using expected_version from RE1 check
        
        if expected_version in current_version_re0:
            print("✓ La version sur RE0 correspond à la version attendue.")
        else:
            raise Exception(f"ERREUR: La version sur RE0 ({current_version_re0}) ne correspond pas à la version attendue ({expected_version}).")

    except Exception as e:
        print(f"Erreur lors de la validation/vérification de RE0 post-redémarrage : {str(e)}")
        raise


    # RÉACTIVATION HA
    # current_connection is to RE1 (Master)
    print("\n7. Réactivation des fonctionnalités de haute disponibilité...")
    try:
        current_connection.config_mode()
        commands_activate_ha = [
            "activate chassis redundancy graceful-switchover",
            "activate routing-options nonstop-routing",
            "activate system commit synchronize",
            # "delete system processes clksyncd-service disable" # If it was set
        ]
        for cmd in commands_activate_ha:
            print(f"Exécution: {cmd}")
            current_connection.send_command_timing(cmd)
        
        print("Application de la réactivation HA (commit synchronize)...")
        current_connection.write_channel("commit synchronize\n")
        time.sleep(5)
        commit_output_ha_reactivate = current_connection.read_until_prompt(read_timeout=300)
        print(commit_output_ha_reactivate)
        if "commit complete" not in commit_output_ha_reactivate.lower() and "commit confirmed" not in commit_output_ha_reactivate.lower():
            if "error" in commit_output_ha_reactivate.lower():
                raise Exception(f"Erreur lors du commit de réactivation HA: {commit_output_ha_reactivate}")
            print("Avertissement: 'commit complete' non détecté clairement après réactivation HA.")

        current_connection.exit_config_mode()
        print("✓ Configuration HA réactivée (ou tentative effectuée).")
    except Exception as e:
        print(f"Erreur lors de la réactivation HA : {str(e)}")
        try: current_connection.exit_config_mode()
        except: pass
        # Non-critical enough to stop switchback, but needs to be noted.
        # For safety, let's raise it. Operator might need to fix HA manually.
        raise


    # BASCULEMENT FINAL VERS RE0
    # current_connection is to RE1 (Master)
    print("\n8. Retour à la configuration d'origine : basculement final vers RE0...")
    try:
        print("Envoi de la commande de basculement (vers RE0)...")
        switch_output_final = current_connection.send_command_timing(
            "request chassis routing-engine master switch",
            strip_prompt=False, strip_command=False
        )
        print(f"Sortie de la demande de basculement final:\n{switch_output_final}")
        
        if "Toggle mastership" in switch_output_final or "yes,no" in switch_output_final:
            current_connection.write_channel("yes\n")
            print("Confirmation 'yes' envoyée pour le basculement final.")
            time.sleep(10)
            print("Attente de la perte de connexion à l'ancien master (RE1)...")
            try:
                current_connection.read_until_prompt(read_timeout=60)
            except Exception as conn_drop_final_ex:
                print(f"Connexion à l'ancien master (RE1) perdue comme attendu: {conn_drop_final_ex}")
        else:
            print("AVERTISSEMENT: Confirmation de basculement final non détectée.")
            
        print("Déconnexion de la session actuelle (vers RE1)...")
        current_connection.disconnect()

        print("Attente du basculement final effectif (environ 5 minutes)...")
        time.sleep(300)

        print("Tentative de reconnexion au routeur (devrait être RE0 maintenant Master)...")
        reconnected_to_original_master = False
        for attempt in range(1, 6):
            print(f"Tentative de reconnexion {attempt}/5...")
            try:
                # current_connection will be re-assigned here for the final check
                current_connection = ConnectHandler(**device_config)
                if not current_connection.is_alive():
                     raise Exception("Connexion échouée (is_alive=False)")

                re_status_final_check = current_connection.send_command("show chassis routing-engine", read_timeout=30)
                lines_re_final_check = re_status_final_check.splitlines()
                re0_is_master_final_check = False
                for i, line in enumerate(lines_re_final_check):
                    if "Slot 0" in line: # RE0
                        for j in range(i + 1, min(i + 5, len(lines_re_final_check))):
                            if "State" in lines_re_final_check[j] and "Master" in lines_re_final_check[j]:
                                re0_is_master_final_check = True
                                break
                        break
                if re0_is_master_final_check:
                    print("✓ Reconnexion réussie. RE0 est maintenant Master (configuration d'origine).")
                    reconnected_to_original_master = True
                    break
                else:
                    print(f"RE0 n'est pas Master. Statut:\n{re_status_final_check}")
                    current_connection.disconnect()
                    if attempt < 5: time.sleep(60)
            except Exception as reconn_final_e:
                print(f"Échec de la tentative de reconnexion {attempt}: {str(reconn_final_e)}")
                if attempt < 5:
                    print("Nouvelle tentative dans 1 minute...")
                    time.sleep(60)
        
        if not reconnected_to_original_master:
            # This is a problem, the system is not in its original mastership state.
            raise Exception("Échec de reconnexion au routeur après basculement final vers RE0 ou RE0 non Master.")

        print("✓ Basculement final vers RE0 réussi.")
        print("\n--- Procédure de mise à jour terminée ---")
        return current_connection # Return the final, active connection to RE0

    except Exception as e:
        print(f"Erreur lors du basculement final vers RE0 : {str(e)}")
        raise # Critical failure