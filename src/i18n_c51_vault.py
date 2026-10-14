"""C5.1 Data Vault locale overlay.

All supported locale catalogs receive the same keys here so the frontend never
falls back through hard-coded copy. Every supported locale now has reviewed
locale-specific Data Vault copy; English is used only for the English catalog.
"""

_EN = {
    "data_vault": "DATA VAULT",
    "data_vault_description": "Encrypt sensitive NetShare server data at rest without encrypting your shared media files.",
    "vault_status": "VAULT STATUS",
    "vault_not_configured": "Not configured",
    "vault_locked": "Locked",
    "vault_unlocked": "Unlocked",
    "vault_mode": "PROTECTION MODE",
    "vault_mode_os": "OS protected",
    "vault_mode_password": "Password protected",
    "vault_mode_os_description": "Transparent protection using your operating system secure credential store for the vault master key.",
    "vault_mode_password_description": "Protect the vault master key with a NetShare password derived through Argon2id.",
    "vault_configure": "CONFIGURE VAULT",
    "vault_unlock": "UNLOCK VAULT",
    "vault_password": "VAULT PASSWORD",
    "vault_current_password": "CURRENT VAULT PASSWORD",
    "vault_new_password": "NEW VAULT PASSWORD",
    "vault_confirm_password": "CONFIRM VAULT PASSWORD",
    "vault_password_mismatch": "Vault passwords do not match.",
    "vault_remember_windows": "Remember on this account",
    "vault_remember_windows_description": "Allows automatic unlock for this OS user by protecting the vault key in the system credential store.",
    "vault_change_mode": "CHANGE MODE",
    "vault_change_password": "CHANGE VAULT PASSWORD",
    "vault_recovery": "RECOVERY KEY",
    "vault_recovery_not_decided": "Recovery setup is not finished.",
    "vault_recovery_enabled": "Recovery key configured",
    "vault_recovery_skipped": "Recovery key deliberately skipped",
    "vault_recovery_generate": "GENERATE RECOVERY KEY",
    "vault_recovery_skip": "SKIP RECOVERY KEY",
    "vault_recovery_warning": "NetShare never stores your recovery key. Keep it somewhere safe and separate from this computer.",
    "vault_recovery_skip_warning": "Without a recovery key, losing the vault password permanently loses access to protected NetShare data.",
    "vault_recovery_skip_confirm": "I understand that if I lose the password, protected data is permanently lost.",
    "vault_recovery_key_title": "SAVE YOUR RECOVERY KEY",
    "vault_recovery_key_description": "This key is shown once. Copy or print it now. NetShare cannot show it again or recover it for you.",
    "vault_recovery_copy": "COPY RECOVERY KEY",
    "vault_recovery_print": "PRINT RECOVERY KEY",
    "vault_recovery_saved": "I SAVED IT",
    "vault_recovery_key_label": "RECOVERY KEY",
    "vault_recover": "RECOVER WITH KEY",
    "vault_recovery_invalid": "The recovery key is invalid.",
    "vault_protected_scope": "PROTECTED DATA",
    "vault_protected_scope_description": "Thumbnails, local session/code databases, transfer/security history, sensitive metadata and internal credential material are encrypted. Shared media files are not encrypted.",
    "vault_configured_success": "Data Vault configured.",
    "vault_unlocked_success": "Data Vault unlocked.",
    "vault_password_changed": "Vault password changed.",
    "vault_mode_changed": "Vault protection mode changed.",
    "vault_password_too_short": "Use at least 8 characters.",
    "vault_operation_failed": "The Data Vault operation could not be completed.",
    "vault_os_unavailable": "OS-protected mode is unavailable because the system credential store could not be accessed. Use Password protected mode instead.",
    "vault_intro_first_title": "PROTECT NETSHARE DATA",
    "vault_intro_update_title": "NEW: DATA VAULT",
    "vault_intro_first_message": "NetShare can now protect its internal sensitive data at rest. Choose transparent operating-system protection or a password-protected vault. Thumbnails, local databases, histories and sensitive metadata are protected; shared media files are not. You can also create a one-time recovery key that NetShare never stores.",
    "vault_intro_update_message": "This update adds Data Vault protection for NetShare internal data. It can encrypt thumbnails, local databases, histories and sensitive metadata without encrypting shared media files. Choose transparent operating-system protection or a password-protected vault, with an optional one-time recovery key that NetShare never stores.",
    "vault_intro_configure_now": "CONFIGURE NOW",
    "vault_intro_defer": "NOT NOW",
    "vault_migration_title": "PROTECTING EXISTING DATA",
    "vault_migration_running": "Encrypting existing NetShare data · {completed}/{total} · {percent}%",
    "vault_migration_failed": "Migration stopped safely. Unlock the vault and retry before starting the server.",
}

_FR = {
    "data_vault": "COFFRE DE DONNÉES",
    "data_vault_description": "Chiffre au repos les données sensibles du serveur NetShare sans chiffrer vos fichiers médias partagés.",
    "vault_status": "ÉTAT DU COFFRE",
    "vault_not_configured": "Non configuré",
    "vault_locked": "Verrouillé",
    "vault_unlocked": "Déverrouillé",
    "vault_mode": "MODE DE PROTECTION",
    "vault_mode_os": "Protégé par le système",
    "vault_mode_password": "Protégé par mot de passe",
    "vault_mode_os_description": "Protection transparente via le stockage sécurisé des identifiants du système pour la clé maître du coffre.",
    "vault_mode_password_description": "Protège la clé maître du coffre avec un mot de passe NetShare dérivé via Argon2id.",
    "vault_configure": "CONFIGURER LE COFFRE",
    "vault_unlock": "DÉVERROUILLER LE COFFRE",
    "vault_password": "MOT DE PASSE DU COFFRE",
    "vault_current_password": "MOT DE PASSE ACTUEL DU COFFRE",
    "vault_new_password": "NOUVEAU MOT DE PASSE DU COFFRE",
    "vault_confirm_password": "CONFIRMER LE MOT DE PASSE DU COFFRE",
    "vault_password_mismatch": "Les mots de passe du coffre ne correspondent pas.",
    "vault_remember_windows": "Mémoriser sur ce compte",
    "vault_remember_windows_description": "Permet le déverrouillage automatique pour cet utilisateur du système en protégeant la clé du coffre dans le stockage sécurisé du système.",
    "vault_change_mode": "CHANGER DE MODE",
    "vault_change_password": "CHANGER LE MOT DE PASSE DU COFFRE",
    "vault_recovery": "CLÉ DE RÉCUPÉRATION",
    "vault_recovery_not_decided": "La configuration de récupération n’est pas terminée.",
    "vault_recovery_enabled": "Clé de récupération configurée",
    "vault_recovery_skipped": "Clé de récupération volontairement ignorée",
    "vault_recovery_generate": "GÉNÉRER UNE CLÉ DE RÉCUPÉRATION",
    "vault_recovery_skip": "IGNORER LA CLÉ DE RÉCUPÉRATION",
    "vault_recovery_warning": "NetShare ne stocke jamais votre clé de récupération. Conservez-la dans un endroit sûr et séparé de cet ordinateur.",
    "vault_recovery_skip_warning": "Sans clé de récupération, la perte du mot de passe entraîne la perte définitive de l’accès aux données NetShare protégées.",
    "vault_recovery_skip_confirm": "Je comprends que si je perds le mot de passe, les données protégées seront définitivement perdues.",
    "vault_recovery_key_title": "ENREGISTREZ VOTRE CLÉ DE RÉCUPÉRATION",
    "vault_recovery_key_description": "Cette clé n’est affichée qu’une fois. Copiez-la ou imprimez-la maintenant. NetShare ne pourra ni la réafficher ni la récupérer.",
    "vault_recovery_copy": "COPIER LA CLÉ DE RÉCUPÉRATION",
    "vault_recovery_print": "IMPRIMER LA CLÉ DE RÉCUPÉRATION",
    "vault_recovery_saved": "JE L’AI ENREGISTRÉE",
    "vault_recovery_key_label": "CLÉ DE RÉCUPÉRATION",
    "vault_recover": "RÉCUPÉRER AVEC LA CLÉ",
    "vault_recovery_invalid": "La clé de récupération est invalide.",
    "vault_protected_scope": "DONNÉES PROTÉGÉES",
    "vault_protected_scope_description": "Les miniatures, bases locales de sessions/codes, historiques de transfert/sécurité, métadonnées sensibles et éléments d’identification internes sont chiffrés. Les fichiers médias partagés ne le sont pas.",
    "vault_configured_success": "Coffre de données configuré.",
    "vault_unlocked_success": "Coffre de données déverrouillé.",
    "vault_password_changed": "Mot de passe du coffre modifié.",
    "vault_mode_changed": "Mode de protection du coffre modifié.",
    "vault_password_too_short": "Utilisez au moins 8 caractères.",
    "vault_operation_failed": "L’opération sur le coffre de données n’a pas pu être effectuée.",
    "vault_os_unavailable": "Le mode protégé par le système est indisponible car le stockage sécurisé du système n’est pas accessible. Utilisez le mode protégé par mot de passe.",
    "vault_intro_first_title": "PROTÉGER LES DONNÉES NETSHARE",
    "vault_intro_update_title": "NOUVEAU : COFFRE DE DONNÉES",
    "vault_intro_first_message": "NetShare peut maintenant protéger au repos ses données internes sensibles. Choisissez la protection transparente du système ou un coffre protégé par mot de passe. Miniatures, bases locales, historiques et métadonnées sensibles sont protégés ; les médias partagés ne le sont pas. Vous pouvez aussi créer une clé de récupération affichée une seule fois et jamais stockée par NetShare.",
    "vault_intro_update_message": "Cette mise à jour ajoute le Coffre de données pour protéger les données internes de NetShare. Il peut chiffrer miniatures, bases locales, historiques et métadonnées sensibles sans chiffrer les médias partagés. Choisissez la protection transparente du système ou un coffre protégé par mot de passe, avec une clé de récupération optionnelle affichée une seule fois et jamais stockée par NetShare.",
    "vault_intro_configure_now": "CONFIGURER MAINTENANT",
    "vault_intro_defer": "PLUS TARD",
    "vault_migration_title": "PROTECTION DES DONNÉES EXISTANTES",
    "vault_migration_running": "Chiffrement des données NetShare existantes · {completed}/{total} · {percent}%",
    "vault_migration_failed": "La migration s’est arrêtée en sécurité. Déverrouillez le coffre et réessayez avant de démarrer le serveur.",
}

_SUPPORTED = ("en", "fr", "ru", "ja", "es", "zh", "ar", "de", "pt", "ko", "tr", "hi", "nl", "it", "tl", "hu", "sw", "id", "vi", "th", "pl", "uk", "fa", "ur", "ms", "ro", "el")

from src.i18n_c51_vault_locales import VAULT_LOCALES

C51_VAULT_TRANSLATIONS = {"en": dict(_EN), "fr": dict(_FR)}
for _language in _SUPPORTED:
    if _language in C51_VAULT_TRANSLATIONS:
        continue
    if _language not in VAULT_LOCALES:
        raise RuntimeError(f"Missing reviewed Data Vault locale: {_language}")
    _values = dict(VAULT_LOCALES[_language])
    if set(_values) != set(_EN):
        missing = sorted(set(_EN) - set(_values))
        extra = sorted(set(_values) - set(_EN))
        raise RuntimeError(f"Invalid Data Vault locale {_language}: missing={missing}, extra={extra}")
    C51_VAULT_TRANSLATIONS[_language] = _values
