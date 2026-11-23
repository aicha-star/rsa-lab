# TP RSA (SEED Labs) pour CyberRangeCZ — guide complet

Scénario CyberRangeCZ construit à partir de `library-junior-hacker` pour le TP *RSA Public-Key Encryption and Signature Lab*.
Pour ~30 étudiants : **chaque étudiant a sa propre VM, ses propres nombres RSA et ses propres flags**. Noté **/20**.

## 1. Contenu du dossier

```
library-rsa-lab/                 ← UN SEUL dossier, même organisation que library-junior-hacker
├── topology.yml                 ← topologie : seed (image seed-ubuntu-20.04, m1.medium, mgmt_user ubuntu) + routeur m1.small
├── variables.yml                ← 6 flags aléatoires générés par la plateforme pour chaque sandbox
├── provisioning/                ← playbook Ansible + rôle "seed" (génère les données uniques de chaque étudiant)
├── training.json                ← définition d'entraînement à IMPORTER dans la plateforme (aucun flag dedans : réponses variables)
├── README.md, LICENSE, ATTRIBUTION.txt
├── LISEZMOI.md                  ← ce guide
└── instructor-only/             ← outils enseignant (solveur, test local). Ignoré par git (.gitignore) : ne pas le publier
```

## 2. Ce qui change par rapport à `library-junior-hacker`

| Élément | Template | Votre TP RSA |
|-|-|-|
| Machine étudiant | `attacker` (kali, standard.small) | `seed` (image **seed-ubuntu-20.04**, **mgmt_user ubuntu**, flavor **m1.medium**) |
| Autres machines | server, client | supprimées (le TP RSA se fait sur une seule machine) |
| Routeur / réseau | debian-12, standard.small, `attacker-switch` 10.1.27.0/24 | debian-12, **m1.small**, `seed-switch` **10.1.33.0/24** (`seed` = .10) : topologie qui a passé l'étape 2 chez vous |
| Compte étudiant | `user` / `Password123` | `seed` / `dees` (créé par le rôle `user-access`) |
| Flags | identiques pour tous | **6 flags aléatoires par sandbox** (`variables.yml` + `variant_answers`) |
| Niveaux | 6 niveaux (nmap, ssh, zip…) | Info, Accès, **Task 1 à 6 du PDF**, quiz final |

## 3. Barème : 20 points, pénalités de 0,5 à 2

| Niveau | Points /20 | Hints (pénalité /20) |
|-|-|-|
| Task 1 — Deriving the private key | 3 | 0,5 · 1 · 2 |
| Task 2 — Encrypting | 3 | 0,5 · 1 · 2 |
| Task 3 — Decrypting | 2 | 0,5 · 1 · 1,5 |
| Task 4 — Signing | 3 | 0,5 · 1 · 1,5 |
| Task 5 — Verifying a signature | 3 | 0,5 · 1 · 2 |
| Task 6 — X.509 certificate | 4 | 0,5 · 1 · 2 |
| Quiz final (4 QCM sur les observations du TP) | 2 | — |
| **Total** | **20** | |

> **Important — la plateforme ne gère que des entiers** (`max_score`, `hint_penalty`, points des questions). Pour pouvoir pénaliser de 0,5 point,
> le barème est exprimé en **demi-points** : la plateforme affiche un maximum de **40**, un hint coûte **1 à 4** points, et
> **note /20 = score plateforme ÷ 2**. Les étudiants sont prévenus dans le niveau « Briefing ».
> Afficher la solution d'un niveau fait perdre tous les points de ce niveau (`solution_penalized`).
> Pour changer le barème : modifier `instructor-only/build_training.py` puis `python3 build_training.py ../training.json`.

## 4. Comment les flags sont uniques et non copiables

* `variables.yml` : la plateforme génère 6 chaînes aléatoires de 10 caractères par sandbox → réponse correcte de chaque niveau (`variant_answers`).
* Tous les nombres du TP sont différents par étudiant : p, q, e, n, d, chiffrés, signatures, certificats X.509 (script `generate_lab.py`, exécuté une seule fois au provisioning puis supprimé).
* Aucun flag n'est écrit en clair sur la VM :
  * Tasks 1 et 3 : le flag est le **texte clair** d'un chiffré RSA → il faut vraiment déchiffrer avec son propre `d`.
  * Tasks 2, 4, 5, 6 : le flag est chiffré en AES-256 et la **clé est le résultat exact du calcul demandé** (chiffré, signatures, vérifications, bloc PKCS#1 du certificat). L'étudiant lance `./unlock.sh <n° de task> <son résultat>`.
* Même un étudiant root sur sa VM (la VM SEED donne sudo) ne peut pas lire les flags sans faire le TP. Les tâches Ansible qui manipulent les flags sont en `no_log`.
* Copier le résultat ou le flag d'un camarade ne marche pas. `minimal_possible_solve_time` est renseigné pour repérer les soumissions trop rapides.

## 5. Prérequis côté cloud (à vérifier avant)

1. Image OpenStack **`seed-ubuntu-20.04`** (Ubuntu SEED), avec l'utilisateur de gestion **`ubuntu`**. C'est le nom de l'image de votre topologie qui a passé l'étape 2 : **l'image nommée seulement `seed` bloquait l'étape 2** (test réseau) lors de mon premier essai chez vous.
2. Flavors **`m1.medium`** (seed) et **`m1.small`** (routeur) disponibles ; le routeur utilise `debian-12-x86_64`.
3. Les sandboxes doivent accéder à Internet (GitHub pour les rôles Ansible `user-access` et `sandbox-logging`, et `apt` seulement si gcc / libssl-dev manquent dans l'image seed — la VM SEED les a déjà).
4. **Ressources pour 30 étudiants** : 30 × (1 VM m1.medium + 1 routeur) en même temps, plus le noeud de gestion de la plateforme. Avec les flavors OpenStack classiques (m1.medium ≈ 2 vCPU / 4 Go, m1.small ≈ 1 vCPU / 2 Go) cela représente de l'ordre de **90 vCPU et 180 Go de RAM**. Vérifiez vos quotas ; sinon faites deux vagues (2 × 15 étudiants) ou demandez une flavor plus petite pour le routeur.

## 6. Étapes de déploiement

1. **Pousser le dépôt Git.** Le dossier `library-rsa-lab/` EST le dépôt (topology.yml, variables.yml, provisioning/ et training.json à la racine, comme le template). `instructor-only/` est exclu par `.gitignore`.
   ```bash
   cd library-rsa-lab
   git init -b main && git add . && git commit -m "RSA lab"
   git remote add origin <URL de votre dépôt GitHub/GitLab>
   git push -u origin main
   ```
   Le dépôt doit être accessible par la plateforme (le plus simple : dépôt public ; il ne contient aucun flag). La doc officielle ne détaille pas les identifiants pour un dépôt privé.
2. **Sandbox Definition** : dans le portail, page *Sandbox Definition Overview* → créer une définition avec l'URL du dépôt (et la révision/branche `main` si demandée). Vérifier qu'elle est acceptée.
3. **Pool** : créer un pool à partir de cette définition, taille **30 + 2 de réserve** (selon vos quotas, §5.4).
4. **Allouer** : cliquer sur le bouton d'allocation du pool et attendre que toutes les étapes d'allocation de chaque sandbox soient terminées (création OpenStack, puis Ansible). Si une étape échoue, ouvrir l'allocation pour lire le log Ansible (§8).
5. **Contrôle rapide d'une sandbox** (recommandé) : ouvrir une sandbox (SSH ou GUI, login `seed` / `dees`), vérifier `ls ~/rsa-lab` (task1…task6, unlock.sh). Option : copier le dossier sur votre PC (`scp -r seed@<ip>:rsa-lab .`) et lancer `python3 instructor-only/solve_all.py rsa-lab` : le script résout les 6 tâches et affiche les 6 flags.
6. **Training Definition** : *Trainings → Definitions* → importer `training.json` (upload, fichier à la racine du dossier). Les niveaux utilisent les variables `flag_task1..6` (réponses variables) ; le nom doit correspondre à `variables.yml`, sinon la plateforme prévient lors de la création de l'instance. Utiliser *Preview* pour relire les textes, puis **Release** la définition.
7. **Training Instance** : créer une instance à partir de la définition (désactiver l'option « local environment »), puis dans *Assign Pool* choisir le pool ; copier le **access token** et le donner aux étudiants. Chaque étudiant qui entre le token reçoit **sa propre sandbox** du pool.
8. **Essai de bout en bout** (fortement conseillé avant le TP) : faites vous-même un run avec le token, résolvez avec `solve_all.py` et soumettez les 6 flags : cela valide la chaîne complète plateforme → variables → Ansible → flags.
9. **Pendant le TP** : suivre la progression dans les visualisations de l'instance. **Après** : lire les résultats, **note /20 = score ÷ 2**, puis détacher et supprimer le pool et l'instance pour libérer le cloud.

## 7. Ce qui a été testé, et ce qui ne l'a pas été

Testé ici (hors plateforme, après la dernière modification de topologie) : le générateur de données (30 sandboxes simulées → toutes les clés et certificats sont distincts), le parcours étudiant complet en C avec l'API BIGNUM d'OpenSSL et les commandes `openssl` du PDF (`instructor-only/test_local.sh`, 9 contrôles), le rôle Ansible `seed` exécuté avec `ansible-playbook` (permissions, nettoyage, absence des flags dans les logs `-vvv`, message d'erreur si variables absentes), la syntaxe du playbook complet avec les vrais rôles externes, et la structure de `training.json` comparée aux fichiers officiels (mêmes clés que le template et la démo).

**Non testé** : l'exécution sur votre plateforme et votre OpenStack (je n'y ai pas accès), donc le nom de l'image `seed`, les flavors, l'accès Internet des sandboxes et l'import de `training.json` restent à vérifier avec l'essai du §6.8. La génération a été éprouvée avec OpenSSL 3 ; la VM SEED Ubuntu 20.04 a OpenSSL 1.1.1, dont toutes les options utilisées (`-pbkdf2`, `x509 -req`, `genrsa`) sont supportées.

## 8. Dépannage

| Symptôme | Cause probable / solution |
|-|-|
| Allocation : « APG variables flag_task1..6 are missing » | `variables.yml` n'est pas à la racine du dépôt poussé, ou le pool a été créé avant le push : repousser, recréer la définition et le pool |
| Allocation : image ou flavor introuvable | adapter `image:` / `flavor:` dans `topology.yml` (seed doit rester `mgmt_user: ubuntu`) |
| Étape 2 (« Networking Ansible Stage ») figée après `Gathering Facts` | problème de réseau de la VM, pas du scénario (l'étape 3 n'a pas démarré). Console de la VM `seed` : `ip -br a` doit montrer `10.1.33.10/24` ; vérifier le nom de l'image dans `topology.yml` |
| Étape 3 : la génération dure ou échoue | la tâche « Run the generator » est limitée à 5 minutes (`async`) : elle échoue avec un message au lieu de bloquer ; normalement elle dure ~1 seconde |
| Allocation : échec au téléchargement d'un rôle | les sandboxes n'ont pas accès à GitHub : vérifier le routeur / le réseau wan |
| Étape `apt` en échec | l'image seed n'a pas gcc / libssl-dev et pas d'accès aux dépôts : les préinstaller dans l'image |
| Message à la création de l'instance sur les noms de variables | `answer_variable_name` ≠ nom dans `variables.yml` : ne pas renommer l'un sans l'autre |
| `unlock.sh` répond « Wrong value » | mauvais résultat ou mauvais ordre des valeurs (S1 puis S2 ; V1 puis V2) ; pour la Task 6, donner **tout** `S^e mod n` et prendre n dans le certificat de la **CA** (`c1.pem`) |
| Un étudiant bloqué par `incorrect_answer_limit` (10 essais) | c'est le comportement prévu ; vérifier la saisie du flag (casse, 0/O, 1/l/I) |

## 9. Personnalisation rapide

* Routeur / flavors : `topology.yml`.
* Compte et mot de passe étudiant : `provisioning/playbook.yml` (rôle `user-access`) **et** le niveau « Get Access » (`instructor-only/build_training.py`).
* Longueur des flags : `variables.yml` (`length`) ; `unlock.sh` accepte 6 à 32 caractères.
* Barème, textes, hints : `instructor-only/build_training.py`, puis régénérer `training.json`.

## 10. Licences

Code : MIT (licence du template conservée). Contenu du TP : SEED Labs (Wenliang Du), CC BY-NC-SA 4.0 — usage non commercial, notice à conserver (voir `ATTRIBUTION.txt`).
