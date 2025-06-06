import os
import warnings
from pathlib import Path
import portalocker

# Fonction pour verrouiller le routeur
def verrouiller_routeur(ip, avant_logs=None):
    warnings.filterwarnings("ignore", category=UserWarning, module="portalocker.utils")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    LOCK_DIR = os.path.join(script_dir, "router_locks")
    Path(LOCK_DIR).mkdir(exist_ok=True, parents=True)
    ip_normalisee = ip.replace('.', '_')
    lock_file = os.path.join(LOCK_DIR, f"{ip_normalisee}.lock")
    if avant_logs is None:
        avant_logs = []
    # Toujours essayer d'acquérir un verrou non-bloquant (même si le fichier existe)
    if os.path.exists(lock_file):
        try:
            test_lock = portalocker.Lock(lock_file, flags=portalocker.LOCK_EX | portalocker.LOCK_NB)
            test_lock.acquire()
            test_lock.release()
        except (portalocker.LockException, BlockingIOError):
            avant_logs.append(f"Le routeur {ip} est déjà verrouillé par un autre processus.")
            print(f"Le routeur {ip} est déjà verrouillé par un autre processus.")
            return None, None
        except Exception as e:
            avant_logs.append(f"Erreur lors du test du verrou : {e}")
            print(f"Erreur lors du test du verrou : {e}")
            return None, None
    # Maintenant acquérir le vrai verrou pour ce processus
    try:
        lock = portalocker.Lock(lock_file, flags=portalocker.LOCK_EX)
        lock.acquire(timeout=5)  # Timeout pour éviter un blocage infini
        print(f"Routeur {ip} verrouillé avec succès.")
        return lock, lock_file
    except portalocker.LockException:
        avant_logs.append(f"Impossible de verrouiller le routeur {ip} (verrou occupé).")
        print(f"Impossible de verrouiller le routeur {ip} (verrou occupé).")

        return None, None
    except Exception as e:
        avant_logs.append(f"Erreur lors du verrouillage : {e}")
        print(f"Erreur lors du verrouillage : {e}")
        if os.path.exists(lock_file):
            os.remove(lock_file)  # Nettoyer le fichier orphelin
        return None, None
    
def liberer_verrou_et_fichier(lock, lock_file_path, avant_logs): # Renamed parameter
    if lock:
        try:
            lock.release()
            avant_logs.append("Verrou libéré.")
        except Exception as e:
            # It's possible the lock was already released or the file handle is bad
            # portalocker might raise an error if trying to release an unacquired lock
            # or if the underlying file descriptor is closed.
            # print(f"Erreur lors de la libération du verrou : {e}") # Potentially noisy
            pass # Suppress error on release if already released or fd invalid
    if lock_file_path and os.path.exists(lock_file_path):
        try:
            os.remove(lock_file_path)
            avant_logs.append(f"Fichier de verrou supprimé: {lock_file_path}")
        except Exception as e:
            avant_logs.append(f"Erreur lors de la suppression du fichier de verrou {lock_file_path}: {e}")