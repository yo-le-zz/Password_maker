#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de Mots de Passe Ultra-Sécurisé
Pas de limite de taille - Cryptographiquement sécurisé
"""

import string
import secrets
import threading
import time
import math
import hashlib
import base64
import json
import os
from getpass import getpass

# Imports optionnels
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ─────────────────────────────────────────────
#   UTILITAIRES
# ─────────────────────────────────────────────

def copy_to_clipboard_secure(text, clear_after=15):
    """Copie le texte dans le presse-papier et l'efface après clear_after secondes"""
    if not CLIPBOARD_AVAILABLE:
        print("⚠️  pyperclip non installé – copie presse-papier indisponible.")
        return
    pyperclip.copy(text)
    print(f"📋 Mot de passe copié dans le presse-papier (effacement dans {clear_after}s)")

    def clear_clip():
        time.sleep(clear_after)
        pyperclip.copy('')
        print("\n🧹 Presse-papier effacé automatiquement.")

    threading.Thread(target=clear_clip, daemon=True).start()


def password_to_key(password: str) -> bytes:
    """Transforme un mot de passe utilisateur en clé Fernet 32 bytes"""
    return hashlib.sha256(password.encode()).digest()


def encrypt_data(data: str, password: str) -> str:
    """Chiffre une chaîne avec Fernet (AES-128-CBC + HMAC)"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Module 'cryptography' non installé.")
    key = password_to_key(password)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.encrypt(data.encode()).decode()


def decrypt_data(token: str, password: str) -> str:
    """Déchiffre un token Fernet"""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Module 'cryptography' non installé.")
    key = password_to_key(password)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.decrypt(token.encode()).decode()


def input_hidden(prompt="Mot de passe maître : "):
    """Saisie masquée"""
    return getpass(prompt)


def sep(char="─", width=70):
    print(char * width)


# ─────────────────────────────────────────────
#   COFFRE-FORT (optionnel, chiffré)
# ─────────────────────────────────────────────

VAULT_FILE = "vault.enc"

def save_to_vault(label: str, password_data: dict, master_password: str):
    """Enregistre un mot de passe chiffré dans le coffre-fort local"""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Module 'cryptography' requis pour le coffre-fort.")
        return

    vault = {}
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "r") as f:
                raw = f.read()
            decrypted = decrypt_data(raw, master_password)
            vault = json.loads(decrypted)
        except Exception:
            print("❌ Impossible de déchiffrer le coffre-fort (mauvais mot de passe maître ?).")
            return

    vault[label] = password_data
    encrypted = encrypt_data(json.dumps(vault, ensure_ascii=False), master_password)
    with open(VAULT_FILE, "w") as f:
        f.write(encrypted)
    print(f"✅ Entrée '{label}' sauvegardée dans le coffre-fort.")


def load_vault(master_password: str) -> dict:
    """Charge et déchiffre le coffre-fort"""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Module 'cryptography' requis pour le coffre-fort.")
        return {}
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r") as f:
            raw = f.read()
        return json.loads(decrypt_data(raw, master_password))
    except Exception:
        print("❌ Déchiffrement impossible. Vérifiez le mot de passe maître.")
        return {}


# ─────────────────────────────────────────────
#   GÉNÉRATEUR
# ─────────────────────────────────────────────

class PasswordGenerator:
    def __init__(self):
        self.lowercase        = string.ascii_lowercase
        self.uppercase        = string.ascii_uppercase
        self.digits           = string.digits
        self.symbols_basic    = "!@#$%^&*"
        self.symbols_extended = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
        self.symbols_all      = "!@#$%^&*()-_=+[]{}\\|;:'\",.<>?/~`"
        self.ambiguous        = "0O1lI"

        # Wordlist enrichie (200+ mots, thèmes variés)
        self.wordlist = [
            # Nature
            "Aigle", "Baleine", "Cerf", "Dauphin", "Elephant", "Flamant",
            "Gorille", "Hibou", "Ibis", "Jaguar", "Koala", "Lemur",
            "Mangouste", "Narval", "Okapi", "Pangolin", "Quetzal", "Raton",
            "Serval", "Tapir", "Urubu", "Vautour", "Wombat", "Xerus",
            "Yack", "Zebre",
            # Géographie
            "Montagne", "Volcan", "Glacier", "Desert", "Savane", "Toundra",
            "Mangrove", "Falaise", "Plateau", "Canyon", "Archipel", "Isthme",
            "Delta", "Geyser", "Lagune", "Marais", "Oasis", "Prairie",
            "Recif", "Steppe", "Torrent", "Vallee",
            # Cosmos
            "Galaxie", "Nebuleuse", "Pulsar", "Quasar", "Supernova", "Comete",
            "Asteroi", "Cosmos", "Photon", "Neutron", "Proton", "Electron",
            "Eclipse", "Solstice", "Equinoxe", "Zenith", "Nadir", "Horizon",
            # Météo
            "Aurore", "Blizzard", "Cyclone", "Deluge", "Eclair", "Foudre",
            "Grele", "Halo", "Isobar", "Jet", "Katabat", "Lidar",
            "Mistral", "Nuage", "Orage", "Pluie", "Rafale", "Soleil",
            "Tempete", "Tonnerre", "Ouragan",
            # Minéraux & Gemmes
            "Amethyste", "Basalte", "Cristal", "Diamant", "Emeraude",
            "Feldspar", "Grenat", "Halite", "Iolite", "Jaspe", "Kunzite",
            "Lazurite", "Malachite", "Natrite", "Olivine", "Pyrite",
            "Quartz", "Rubis", "Saphir", "Topaze", "Uvarovit", "Vesuvian",
            # Mythologie & Fantasy
            "Dragon", "Licorne", "Phoenix", "Griffon", "Minotaure", "Sphinx",
            "Basilic", "Chimere", "Kraken", "Leviatan", "Manticore", "Nymphe",
            "Ogre", "Pegase", "Roc", "Sirene", "Titan", "Vampire",
            "Wendigo", "Yeti", "Zombie",
            # Sciences & Tech
            "Algorithme", "Binaire", "Chiffrement", "Donnees", "Encodage",
            "Firmware", "Gigaoctet", "Hexadecimal", "Internet", "Java",
            "Kernel", "Linux", "Matrix", "Neurone", "Octet", "Protocole",
            "Quantum", "Reseau", "Serveur", "Terminal", "Ubuntu",
            # Couleurs poétiques
            "Azur", "Carmin", "Ecarlate", "Fuchsia", "Indigo", "Jade",
            "Kaki", "Lilas", "Magenta", "Noir", "Ocre", "Pourpre",
            "Rubis", "Safran", "Turquoise",
            # Musique
            "Allegro", "Basse", "Corde", "Diapason", "Fugue", "Gamme",
            "Harmonie", "Intervalle", "Jazz", "Largo", "Melodie", "Note",
            "Octave", "Piano", "Riff", "Sonate", "Tempo", "Vibrato",
            # Divers mémorables
            "Aventure", "Brume", "Cascade", "Enigme", "Epopee", "Fable",
            "Heroine", "Illusion", "Intrigue", "Legende", "Mystere",
            "Oracle", "Paradoxe", "Saga", "Tresor", "Vision",
        ]

    # ── Générateur principal ──────────────────

    def generate(self, length=32, use_lowercase=True, use_uppercase=True,
                 use_digits=True, use_symbols=True, symbols_level="basic",
                 exclude_ambiguous=False, custom_chars="",
                 min_each_type=True):
        """
        Génère un mot de passe cryptographiquement sécurisé.

        Args:
            length           (int)  : Longueur souhaitée (≥ 1)
            use_lowercase    (bool) : Inclure a-z
            use_uppercase    (bool) : Inclure A-Z
            use_digits       (bool) : Inclure 0-9
            use_symbols      (bool) : Inclure symboles
            symbols_level    (str)  : "basic" | "extended" | "all"
            exclude_ambiguous(bool) : Exclure 0,O,1,l,I
            custom_chars     (str)  : Caractères supplémentaires
            min_each_type    (bool) : Garantir au moins 1 char de chaque type activé

        Returns:
            str : Mot de passe généré
        """
        charset = ""
        mandatory_pools = []

        if use_lowercase:
            pool = self.lowercase
            if exclude_ambiguous:
                pool = ''.join(c for c in pool if c not in self.ambiguous)
            charset += pool
            mandatory_pools.append(pool)

        if use_uppercase:
            pool = self.uppercase
            if exclude_ambiguous:
                pool = ''.join(c for c in pool if c not in self.ambiguous)
            charset += pool
            mandatory_pools.append(pool)

        if use_digits:
            pool = self.digits
            if exclude_ambiguous:
                pool = ''.join(c for c in pool if c not in self.ambiguous)
            charset += pool
            mandatory_pools.append(pool)

        if use_symbols:
            if symbols_level == "extended":
                pool = self.symbols_extended
            elif symbols_level == "all":
                pool = self.symbols_all
            else:
                pool = self.symbols_basic
            charset += pool
            mandatory_pools.append(pool)

        if custom_chars:
            charset += custom_chars

        if exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.ambiguous)

        # Dédoublonnage
        charset = ''.join(dict.fromkeys(charset))

        if not charset:
            raise ValueError("❌ Aucun type de caractère sélectionné !")

        # Garantie de présence d'au moins 1 char par type
        if min_each_type and length >= len(mandatory_pools):
            mandatory = [secrets.choice(p) for p in mandatory_pools if p]
            remaining = length - len(mandatory)
            rest = [secrets.choice(charset) for _ in range(remaining)]
            password_list = mandatory + rest
            secrets.SystemRandom().shuffle(password_list)
            return ''.join(password_list)

        return ''.join(secrets.choice(charset) for _ in range(length))

    # ── Passphrase ────────────────────────────

    def generate_passphrase(self, num_words=6, separator="-", capitalize=True,
                            add_number=True, add_symbol=True, word_transform="none"):
        """
        Génère une passphrase mémorable.

        Args:
            num_words      (int) : Nombre de mots
            separator      (str) : Séparateur
            capitalize     (bool): Majuscule initiale
            add_number     (bool): Nombre aléatoire à la fin
            add_symbol     (bool): Symbole à la fin
            word_transform (str) : "none" | "upper" | "lower" | "alternating"

        Returns:
            str : Passphrase
        """
        words = [secrets.choice(self.wordlist) for _ in range(num_words)]

        if word_transform == "upper":
            words = [w.upper() for w in words]
        elif word_transform == "lower":
            words = [w.lower() for w in words]
        elif word_transform == "alternating":
            words = [w.upper() if i % 2 == 0 else w.lower() for i, w in enumerate(words)]
        elif capitalize:
            words = [w.capitalize() for w in words]

        passphrase = separator.join(words)

        if add_number:
            passphrase += str(secrets.randbelow(10000)).zfill(4)

        if add_symbol:
            passphrase += secrets.choice("!@#$%&*?")

        return passphrase

    # ── PIN numérique ─────────────────────────

    def generate_pin(self, length=6, no_repeats=False, no_sequential=False):
        """
        Génère un code PIN numérique sécurisé.

        Args:
            length        (int) : Nombre de chiffres
            no_repeats    (bool): Interdire les chiffres répétés
            no_sequential (bool): Interdire les séquences (123, 987…)

        Returns:
            str : PIN
        """
        while True:
            pin = ''.join(str(secrets.randbelow(10)) for _ in range(length))

            if no_repeats and len(set(pin)) != len(pin):
                continue

            if no_sequential:
                seq = False
                for i in range(len(pin) - 2):
                    a, b, c = int(pin[i]), int(pin[i+1]), int(pin[i+2])
                    if (b == a + 1 == c - 1) or (b == a - 1 == c + 1):
                        seq = True
                        break
                if seq:
                    continue

            return pin

    # ── Entropie & estimation ─────────────────

    def calculate_entropy(self, password):
        """Calcule l'entropie d'un mot de passe en bits"""
        charset_size = 0
        if any(c in self.lowercase for c in password):
            charset_size += 26
        if any(c in self.uppercase for c in password):
            charset_size += 26
        if any(c in self.digits for c in password):
            charset_size += 10
        if any(c in self.symbols_all for c in password):
            charset_size += len(self.symbols_all)
        # Caractères unicode hors ASCII
        if any(ord(c) > 127 for c in password):
            charset_size += 128

        if charset_size == 0:
            return 0

        return len(password) * math.log2(charset_size)

    def estimate_crack_time(self, entropy_bits, attempts_per_second=1_000_000_000):
        """
        Estime le temps pour casser un mot de passe par force brute.

        Args:
            entropy_bits         (float): Entropie en bits
            attempts_per_second  (int)  : Vitesse d'attaque (défaut = 1 Ghash/s GPU)

        Returns:
            str : Temps humainement lisible
        """
        if entropy_bits <= 0:
            return "instantané"

        total = 2 ** entropy_bits
        seconds = total / (2 * attempts_per_second)

        units = [
            (31_536_000 * 1_000_000_000, "milliards d'années"),
            (31_536_000 * 1_000_000,     "millions d'années"),
            (31_536_000 * 1_000,         "milliers d'années"),
            (31_536_000,                 "années"),
            (86_400,                     "jours"),
            (3_600,                      "heures"),
            (60,                         "minutes"),
            (1,                          "secondes"),
        ]

        for divisor, label in units:
            if seconds >= divisor:
                value = seconds / divisor
                return f"{value:.2f} {label}"

        return f"{seconds:.4f} secondes"

    def strength_label(self, entropy: float) -> str:
        """Retourne une étiquette de force en fonction de l'entropie"""
        if entropy < 28:
            return "💀 CATASTROPHIQUE"
        elif entropy < 40:
            return "❌ TRÈS FAIBLE"
        elif entropy < 60:
            return "⚠️  FAIBLE"
        elif entropy < 80:
            return "🟡 MOYEN"
        elif entropy < 100:
            return "✅ BON"
        elif entropy < 128:
            return "🛡️  TRÈS BON"
        else:
            return "🔐 EXCELLENT"

    def full_analysis(self, password: str):
        """Affiche une analyse complète d'un mot de passe"""
        entropy    = self.calculate_entropy(password)
        crack_time = self.estimate_crack_time(entropy)
        strength   = self.strength_label(entropy)

        has_lower  = any(c in self.lowercase for c in password)
        has_upper  = any(c in self.uppercase for c in password)
        has_digit  = any(c in self.digits for c in password)
        has_symbol = any(c in self.symbols_all for c in password)
        has_unicode = any(ord(c) > 127 for c in password)
        has_ambig  = any(c in self.ambiguous for c in password)

        # Comptage des caractères uniques
        unique_chars = len(set(password))

        sep()
        print("📊 ANALYSE DÉTAILLÉE")
        sep()
        print(f"  📏 Longueur         : {len(password)} caractères")
        print(f"  🔤 Minuscules       : {'✅' if has_lower  else '❌'}")
        print(f"  🔠 Majuscules       : {'✅' if has_upper  else '❌'}")
        print(f"  🔢 Chiffres         : {'✅' if has_digit  else '❌'}")
        print(f"  🔣 Symboles         : {'✅' if has_symbol else '❌'}")
        print(f"  🌍 Unicode étendu   : {'✅' if has_unicode else '❌'}")
        print(f"  👁️  Caract. ambigus  : {'⚠️  Présents' if has_ambig else '✅ Absents'}")
        print(f"  🎨 Chars uniques    : {unique_chars} / {len(password)}")
        print(f"  🔒 Entropie         : {entropy:.1f} bits")
        print(f"  ⏱️  Temps attaque    : {crack_time}")
        print(f"  💪 Force            : {strength}")
        sep()


# ─────────────────────────────────────────────
#   INTERFACE PRINCIPALE
# ─────────────────────────────────────────────

def main():
    gen = PasswordGenerator()

    print()
    sep("═")
    print("        🔐 GÉNÉRATEUR DE MOTS DE PASSE ULTRA-SÉCURISÉ 🔐")
    sep("═")

    if not CLIPBOARD_AVAILABLE:
        print("  ℹ️  Astuce : installez pyperclip pour la copie automatique.")
    if not CRYPTO_AVAILABLE:
        print("  ℹ️  Astuce : installez cryptography pour le coffre-fort chiffré.")
    print()

    while True:
        print("\n📋 MENU PRINCIPAL")
        sep("─", 45)
        print("  1. Générer un mot de passe aléatoire")
        print("  2. Générer une passphrase mémorable")
        print("  3. Analyser un mot de passe")
        print("  4. Générer plusieurs mots de passe")
        print("  5. Générer un code PIN")
        print("  6. Coffre-fort (sauvegarder / consulter)")
        print("  7. Quitter")
        sep("─", 45)

        choice = input("➤ Votre choix (1-7) : ").strip()

        # ── 1. Mot de passe unique ──────────────────────────────────────────
        if choice == "1":
            print()
            sep("═")
            print("  🎲 GÉNÉRATION DE MOT DE PASSE ALÉATOIRE")
            sep("═")

            while True:
                try:
                    length = int(input("\n➤ Longueur (ex : 32, 64, 128) : "))
                    if length < 1:
                        print("❌ La longueur doit être ≥ 1."); continue
                    if length > 10_000:
                        if input(f"⚠️  {length} caractères – confirmer ? (o/n) : ").lower() != 'o':
                            continue
                    break
                except ValueError:
                    print("❌ Entrez un nombre entier valide.")

            use_lower   = input("➤ Minuscules (a-z) ?           [O/n] : ").strip().lower() != 'n'
            use_upper   = input("➤ Majuscules (A-Z) ?           [O/n] : ").strip().lower() != 'n'
            use_digits  = input("➤ Chiffres (0-9) ?             [O/n] : ").strip().lower() != 'n'
            use_symbols = input("➤ Symboles (!@#$…) ?           [O/n] : ").strip().lower() != 'n'

            symbols_level = "basic"
            if use_symbols:
                print("\n  Niveau des symboles :")
                print("    1. Basique   : !@#$%^&*")
                print("    2. Étendu    : !@#$%^&*()-_=+[]{}|;:,.<>?/~`")
                print("    3. Tous      : tous les symboles possibles")
                sym = input("  ➤ Choix (1/2/3) [1] : ").strip() or "1"
                symbols_level = {"1": "basic", "2": "extended", "3": "all"}.get(sym, "basic")

            exclude_amb  = input("➤ Exclure ambigus (0,O,1,l,I) ? [o/N] : ").strip().lower() == 'o'
            min_types    = input("➤ Garantir au moins 1 char de chaque type ? [O/n] : ").strip().lower() != 'n'
            custom       = input("➤ Caractères personnalisés (ou Entrée) : ").strip()

            try:
                password = gen.generate(
                    length=length,
                    use_lowercase=use_lower,
                    use_uppercase=use_upper,
                    use_digits=use_digits,
                    use_symbols=use_symbols,
                    symbols_level=symbols_level,
                    exclude_ambiguous=exclude_amb,
                    custom_chars=custom,
                    min_each_type=min_types,
                )

                entropy    = gen.calculate_entropy(password)
                crack_time = gen.estimate_crack_time(entropy)
                strength   = gen.strength_label(entropy)

                print()
                sep("═")
                print("  ✅ MOT DE PASSE GÉNÉRÉ :")
                sep("─")
                print(f"\n  {password}\n")
                sep("─")
                print(f"  📏 Longueur   : {len(password)} caractères")
                print(f"  🔒 Entropie   : {entropy:.1f} bits")
                print(f"  ⏱️  Temps crack : {crack_time}")
                print(f"  💪 Force      : {strength}")
                sep("═")

                if CLIPBOARD_AVAILABLE and input("\n➤ Copier dans le presse-papier ? [O/n] : ").strip().lower() != 'n':
                    copy_to_clipboard_secure(password)

                if CRYPTO_AVAILABLE and input("➤ Sauvegarder dans le coffre-fort ? [o/N] : ").strip().lower() == 'o':
                    label  = input("  Nom/étiquette de l'entrée : ").strip() or "sans_nom"
                    master = input_hidden("  Mot de passe maître : ")
                    save_to_vault(label, {"password": password, "entropy": entropy}, master)

            except ValueError as e:
                print(f"\n{e}")

        # ── 2. Passphrase ───────────────────────────────────────────────────
        elif choice == "2":
            print()
            sep("═")
            print("  📝 GÉNÉRATION DE PASSPHRASE MÉMORABLE")
            sep("═")

            while True:
                try:
                    num_words = int(input("\n➤ Nombre de mots (recommandé : 5-8) : "))
                    if num_words < 2:
                        print("❌ Minimum 2 mots."); continue
                    break
                except ValueError:
                    print("❌ Entrez un nombre entier valide.")

            separator = input("➤ Séparateur ['-'] : ").strip() or "-"

            print("\n  Transformation des mots :")
            print("    1. Majuscule initiale (Mot)")
            print("    2. Tout en majuscules (MOT)")
            print("    3. Tout en minuscules (mot)")
            print("    4. Alternance (MOT-mot-MOT-…)")
            tr_choice = input("  ➤ Choix (1/2/3/4) [1] : ").strip() or "1"
            transform_map = {"1": "none", "2": "upper", "3": "lower", "4": "alternating"}
            transform = transform_map.get(tr_choice, "none")
            capitalize = (tr_choice in ("1", ""))

            add_number = input("➤ Ajouter un nombre à la fin ? [O/n] : ").strip().lower() != 'n'
            add_symbol = input("➤ Ajouter un symbole à la fin ? [O/n] : ").strip().lower() != 'n'

            passphrase = gen.generate_passphrase(
                num_words=num_words,
                separator=separator,
                capitalize=capitalize,
                add_number=add_number,
                add_symbol=add_symbol,
                word_transform=transform if tr_choice != "1" else "none",
            )

            entropy    = gen.calculate_entropy(passphrase)
            crack_time = gen.estimate_crack_time(entropy)
            strength   = gen.strength_label(entropy)

            print()
            sep("═")
            print("  ✅ PASSPHRASE GÉNÉRÉE :")
            sep("─")
            print(f"\n  {passphrase}\n")
            sep("─")
            print(f"  📏 Longueur   : {len(passphrase)} caractères")
            print(f"  🔒 Entropie   : {entropy:.1f} bits")
            print(f"  ⏱️  Temps crack : {crack_time}")
            print(f"  💪 Force      : {strength}")
            sep("═")

            if CLIPBOARD_AVAILABLE and input("\n➤ Copier dans le presse-papier ? [O/n] : ").strip().lower() != 'n':
                copy_to_clipboard_secure(passphrase)

        # ── 3. Analyse ──────────────────────────────────────────────────────
        elif choice == "3":
            print()
            sep("═")
            print("  🔍 ANALYSE DE MOT DE PASSE")
            sep("═")

            mode = input("\n  Saisie visible (v) ou masquée (m) ? [m] : ").strip().lower() or "m"
            if mode == "v":
                password = input("➤ Mot de passe : ")
            else:
                password = input_hidden("➤ Mot de passe (masqué) : ")

            if not password:
                print("❌ Mot de passe vide."); continue

            gen.full_analysis(password)

        # ── 4. Génération multiple ──────────────────────────────────────────
        elif choice == "4":
            print()
            sep("═")
            print("  🎲 GÉNÉRATION MULTIPLE")
            sep("═")

            while True:
                try:
                    count = int(input("\n➤ Nombre de mots de passe (1-100) : "))
                    if 1 <= count <= 100: break
                    print("❌ Entrez un nombre entre 1 et 100.")
                except ValueError:
                    print("❌ Nombre entier requis.")

            while True:
                try:
                    length = int(input("➤ Longueur de chaque mot de passe : "))
                    if length >= 1: break
                    print("❌ La longueur doit être ≥ 1.")
                except ValueError:
                    print("❌ Nombre entier requis.")

            use_symbols = input("➤ Inclure des symboles ?        [O/n] : ").strip().lower() != 'n'
            exclude_amb = input("➤ Exclure ambigus (0,O,1,l,I) ? [o/N] : ").strip().lower() == 'o'

            print()
            sep("═")
            print(f"  ✅ {count} MOTS DE PASSE ({length} caractères chacun) :")
            sep("─")
            passwords = []
            for i in range(count):
                pw = gen.generate(
                    length=length,
                    use_symbols=use_symbols,
                    exclude_ambiguous=exclude_amb,
                )
                passwords.append(pw)
                entropy = gen.calculate_entropy(pw)
                print(f"  {i+1:3d}. {pw}  [{entropy:.0f} bits]")
            sep("═")

            if CLIPBOARD_AVAILABLE and count == 1:
                if input("\n➤ Copier le mot de passe ? [O/n] : ").strip().lower() != 'n':
                    copy_to_clipboard_secure(passwords[0])

        # ── 5. PIN ──────────────────────────────────────────────────────────
        elif choice == "5":
            print()
            sep("═")
            print("  🔢 GÉNÉRATEUR DE CODE PIN")
            sep("═")

            while True:
                try:
                    pin_len = int(input("\n➤ Longueur du PIN (4-12) : "))
                    if 4 <= pin_len <= 12: break
                    print("❌ Longueur entre 4 et 12.")
                except ValueError:
                    print("❌ Nombre entier requis.")

            no_rep = input("➤ Interdire les chiffres répétés ?   [o/N] : ").strip().lower() == 'o'
            no_seq = input("➤ Interdire les séquences (123…) ?   [o/N] : ").strip().lower() == 'o'

            pin = gen.generate_pin(length=pin_len, no_repeats=no_rep, no_sequential=no_seq)

            print()
            sep("─")
            print(f"\n  🔢 PIN généré : {pin}\n")
            sep("─")

            if CLIPBOARD_AVAILABLE and input("➤ Copier le PIN ? [O/n] : ").strip().lower() != 'n':
                copy_to_clipboard_secure(pin, clear_after=10)

        # ── 6. Coffre-fort ──────────────────────────────────────────────────
        elif choice == "6":
            if not CRYPTO_AVAILABLE:
                print("\n⚠️  Module 'cryptography' non installé. Installez-le avec :")
                print("   pip install cryptography")
                continue

            print()
            sep("═")
            print("  🗄️  COFFRE-FORT CHIFFRÉ")
            sep("═")
            print("  1. Ajouter une entrée manuellement")
            print("  2. Afficher toutes les entrées")
            vault_choice = input("➤ Choix : ").strip()

            master = input_hidden("\n➤ Mot de passe maître : ")

            if vault_choice == "1":
                label    = input("➤ Étiquette (ex: email_pro) : ").strip()
                password = input_hidden("➤ Mot de passe à stocker : ")
                notes    = input("➤ Notes (optionnel) : ").strip()
                entry    = {"password": password}
                if notes:
                    entry["notes"] = notes
                save_to_vault(label, entry, master)

            elif vault_choice == "2":
                vault = load_vault(master)
                if not vault:
                    print("  ℹ️  Coffre-fort vide ou non trouvé.")
                else:
                    sep("─")
                    for label, data in vault.items():
                        print(f"\n  🔑 {label}")
                        print(f"     Mot de passe : {data.get('password', '?')}")
                        if "notes" in data:
                            print(f"     Notes        : {data['notes']}")
                    sep("─")
            else:
                print("❌ Choix invalide.")

        # ── 7. Quitter ──────────────────────────────────────────────────────
        elif choice == "7":
            print("\n👋 Au revoir ! Restez en sécurité. 🔐\n")
            break

        else:
            print("\n❌ Choix invalide. Entrez un nombre de 1 à 7.")


# ─────────────────────────────────────────────
#   POINT D'ENTRÉE
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Programme interrompu. Au revoir !\n")
    except Exception as e:
        print(f"\n❌ Erreur inattendue : {e}\n")