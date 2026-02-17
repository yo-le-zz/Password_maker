# 🔐 Password Maker

> Générateur de mots de passe ultra-sécurisé — cryptographiquement sûr, sans limite de taille, avec coffre-fort chiffré intégré.

<p align="center">
  <img src="assets/banner.png" alt="Password Maker Banner" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/yo-le-zz/Password_maker?style=flat-square&color=brightgreen" alt="Release"/>
  <img src="https://img.shields.io/github/license/yo-le-zz/Password_maker?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square" alt="Python"/>
  <img src="https://img.shields.io/badge/plateforme-Windows-0078d7?style=flat-square&logo=windows" alt="Windows"/>
</p>

---

## ✨ Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| 🎲 **Mot de passe aléatoire** | Longueur illimitée, tous types de caractères configurables |
| 📝 **Passphrase mémorable** | Style « Correct-Horse-Battery-Staple », 200+ mots |
| 🔢 **Code PIN** | Anti-répétition et anti-séquence optionnels |
| 🔍 **Analyseur** | Entropie en bits, temps de crack estimé, composition |
| 🗄️ **Coffre-fort chiffré** | Stockage local AES-128 (Fernet), mot de passe maître |
| 📋 **Presse-papier sécurisé** | Copie automatique + effacement après N secondes |
| 🔒 **Générateur multiple** | Jusqu'à 100 mots de passe en une seule fois |

---

## 🖥️ Interface

```
╔══════════════════════════════════════════════════════════════╗
║        🔐 GÉNÉRATEUR DE MOTS DE PASSE ULTRA-SÉCURISÉ 🔐     ║
╚══════════════════════════════════════════════════════════════╝

📋 MENU PRINCIPAL
─────────────────────────────────────────────
  1. Générer un mot de passe aléatoire
  2. Générer une passphrase mémorable
  3. Analyser un mot de passe
  4. Générer plusieurs mots de passe
  5. Générer un code PIN
  6. Coffre-fort (sauvegarder / consulter)
  7. Quitter
```

---

## 🚀 Installation rapide

### Via l'installateur (recommandé)

1. Télécharge l'installateur : [`Password_maker_installer.exe`](https://github.com/yo-le-zz/Password_maker/releases/latest)
2. Lance-le et suis les étapes (README → Licence → Chemin → Raccourci)

### Installation manuelle

```bash
# Cloner le dépôt
git clone https://github.com/yo-le-zz/Password_maker.git
cd Password_maker

# Installer les dépendances
pip install -r requirements.txt

# Lancer
python password_generator.py
```

---

## 📦 Dépendances

```
cryptography
pyperclip
```

> **Note :** Le programme fonctionne sans `pyperclip` (copie presse-papier désactivée) et sans `cryptography` (coffre-fort désactivé).

Installe tout d'un coup :

```bash
pip install cryptography pyperclip
```

---

## 🔐 Sécurité

- Génération via `secrets.choice()` — cryptographiquement sécurisé (CSPRNG)
- Aucun mot de passe transmis sur le réseau
- Coffre-fort chiffré localement avec **Fernet (AES-128-CBC + HMAC-SHA256)**
- Le presse-papier est **effacé automatiquement** après 15 secondes
- Les mots de passe maîtres ne sont jamais stockés en clair

### Entropie de référence

| Longueur | Types | Entropie | Temps crack (GPU) |
|---|---|---|---|
| 8 car. | minusc. seul. | ~37 bits | quelques heures |
| 12 car. | tous types | ~78 bits | des millions d'années |
| 20 car. | tous types | ~131 bits | astronomique |
| 6 mots | passphrase | ~85+ bits | astronomique |

---

## 📁 Structure du projet

```
Password_maker/
├── Binairy file/           # Exécutable Windows
│   └── Password_maker.exe
├── assets/                 # Ressources (icônes, images…)
│   └── ...
├── password_generator.py   # Script principal
├── installer.py            # Installateur
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 📖 Utilisation

### Générer un mot de passe

```
➤ Longueur (ex : 32, 64, 128) : 32
➤ Minuscules (a-z) ?           [O/n] : 
➤ Majuscules (A-Z) ?           [O/n] : 
➤ Chiffres (0-9) ?             [O/n] : 
➤ Symboles (!@#$…) ?           [O/n] : 

✅ MOT DE PASSE GÉNÉRÉ :
  q7!Tz#mK2vXp@nRw$jL5&eYd*uQs^cF

  📏 Longueur   : 32 caractères
  🔒 Entropie   : 210.1 bits
  ⏱️  Temps crack : 3.24e+47 milliards d'années
  💪 Force      : 🔐 EXCELLENT
```

### Générer une passphrase

```
➤ Nombre de mots (recommandé : 5-8) : 6
➤ Séparateur ['-'] : 
➤ Transformation : 1 (Majuscule initiale)
➤ Ajouter un nombre ? [O/n] : 
➤ Ajouter un symbole ? [O/n] : 

✅ PASSPHRASE GÉNÉRÉE :
  Glacier-Nebuleuse-Phoenix-Saphir-Torrent-Volcan3847!
```

### Analyser un mot de passe

```
📊 ANALYSE DÉTAILLÉE
──────────────────────────────────────────────────────────────────────
  📏 Longueur         : 20 caractères
  🔤 Minuscules       : ✅
  🔠 Majuscules       : ✅
  🔢 Chiffres         : ✅
  🔣 Symboles         : ✅
  🌍 Unicode étendu   : ❌
  👁️  Caract. ambigus  : ✅ Absents
  🎨 Chars uniques    : 19 / 20
  🔒 Entropie         : 131.1 bits
  ⏱️  Temps attaque    : 2.04e+21 milliards d'années
  💪 Force            : 🔐 EXCELLENT
```

---

## 🛡️ Coffre-fort

Les mots de passe sont stockés dans un fichier `vault.enc` chiffré localement.

```
➤ Votre choix (1-7) : 6
➤ Mot de passe maître : ••••••••
  1. Ajouter une entrée
  2. Afficher toutes les entrées
```

> ⚠️ Si vous perdez votre mot de passe maître, les données du coffre-fort sont **irrécupérables**.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [`LICENSE`](LICENSE) pour plus de détails.

---

## 👤 Auteur

**yo-le-zz** — [GitHub](https://github.com/yo-le-zz)

---

<p align="center">
  Fait avec ❤️ et <code>secrets.choice()</code>
</p>
