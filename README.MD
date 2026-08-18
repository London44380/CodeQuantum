<h1 align="center">codequantum</h1>
<p align="center"><b>Post-Quantum Compatibility Scanner</b></p>
<p align="center">
  Audite un hôte, une IP ou une liste de cibles et identifie <i>précisément</i> quels algorithmes,
  certificats et protocoles casseront avec l'arrivée d'un ordinateur quantique cryptographiquement pertinent —
  avec une timeline de migration priorisée et actionnable.
</p>

---

## Pourquoi cet outil existe

La plupart des scanners TLS te disent "TLS 1.3 : oui" et s'arrêtent là. Aucun ne répond à la vraie question :
**mon infra survit-elle à la transition post-quantique, et dans quel ordre dois-je agir ?**

`codequantum` sépare deux horloges très différentes :

| Horloge | Signification | Urgence |
|---|---|---|
| **HNDL** (*Harvest Now, Decrypt Later*) | Le trafic enregistré **aujourd'hui** sera déchiffrable rétroactivement le jour où un ordinateur quantique existera. Échange de clés classique uniquement. | **Immédiate** — le compteur tourne déjà. |
| **Q-DAY** | Signatures et identité (certificats). Ne casse **que** le jour où la machine existe. | Planifiable, sur le calendrier d'expiration des certificats. |

Un troisième état existe aussi, et c'est important : **UNDETERMINED**. Si l'outil ne peut pas tester quelque chose
(par exemple parce que l'OpenSSL local est trop ancien pour proposer les groupes hybrides ML-KEM), il le dit
clairement — plutôt que d'afficher un faux "non supporté". Beaucoup d'outils confondent *"je n'ai pas pu tester"*
et *"ce n'est pas supporté"* ; celui-ci ne le fait jamais.

## Ce que le scanner vérifie

- **Échange de clés post-quantique (TLS)** — support et préférence réelle de X25519MLKEM768 / SecP256r1MLKEM768
- **Échange de clés post-quantique (SSH)** — sntrup761x25519, mlkem768x25519, et leur ordre de préférence
- **Certificats** — algorithme de clé, algorithme de signature, dates d'expiration vs. les échéances NIST IR 8547
  (dépréciation 2030, interdiction 2035), chaîne complète (leaf + intermédiaires)
- **Protocoles obsolètes** — TLS 1.0/1.1, ciphers faibles (RC4, DES, 3DES...), signatures MD5/SHA-1
- **SSH** — host keys, MACs faibles, ordre de préférence des algorithmes

## Installation

```bash
git clone <url-de-ton-forgejo>/codequantum.git
cd codequantum
pip install cryptography --break-system-packages
```

Prérequis système : `openssl` en ligne de commande.

> **Pour tester réellement le support post-quantique** (pas juste UNDETERMINED), ton OpenSSL local doit pouvoir
> offrir les groupes hybrides ML-KEM : OpenSSL ≥ 3.5, ou OpenSSL antérieur + [`oqs-provider`](https://github.com/open-quantum-safe/oqs-provider).
> Sans ça, le scanner reste honnête et rapporte `UNDETERMINED` plutôt qu'un faux négatif.

## Utilisation

```bash
# Un seul hôte
python3 codequantum.py example.com

# IP + ports personnalisés
python3 codequantum.py 192.168.1.10 --ports 443,22,8443

# Liste de cibles, rapport JSON + texte
python3 codequantum.py -f targets.txt --json report.json -o report.txt

# Vérifier que le scanner discrimine vraiment (contrôles positifs/négatifs)
python3 codequantum.py --self-test
```

## Exemple de sortie

```
==========================================================================
  POST-QUANTUM EXPOSURE REPORT
==========================================================================

  targets: 1    HIGH: 2  MEDIUM: 6  INFO: 7

  P1 - HARVEST NOW, DECRYPT LATER  (2 findings)
  Traffic recorded today is decrypted retroactively on Q-day.
  This clock is ALREADY RUNNING. Fix these first.

    HIGH     example.com:443/tls  PQ supported but not preferred (default: X25519, 253 bits)
             -> Move the hybrid PQ group to the front of the server's group preference list.

  P3 - Q-DAY / SCHEDULABLE  (6)
  Signatures and identity. Fails only when the machine exists;
  plan against certificate expiry, do not panic.

    MEDIUM   example.com:443/tls/cert/leaf  Quantum-vulnerable certificate key: ECDSA-secp256r1-256
```

## Le `--self-test`, ou pourquoi faire confiance au résultat

Un scanner qui ne peut jamais dire "non" n'a aucune valeur. `--self-test` vérifie que l'outil sait vraiment
distinguer un hôte conforme d'un hôte qui ne l'est pas, via de vrais contrôles positifs et négatifs
(ex. `github.com` refuse TLS 1.0, `badssl.com` le propose exprès) — et vérifie que le classificateur n'invente
jamais un verdict post-quantique quand il ne peut pas réellement tester.

## Confidentialité

Le scanner ne contacte que les cibles que **tu** lui donnes en argument, plus trois hôtes publics
(`github.com`, `cloudflare.com`, `badssl.com`) utilisés uniquement par `--self-test` comme contrôles de référence.
Aucune télémétrie, aucun appel réseau caché, aucune donnée envoyée ailleurs que dans les fichiers de rapport
que tu génères toi-même en local.

## Feuille de route de migration (référence NIST IR 8547, brouillon initial)

| Échéance | Action |
|---|---|
| **Maintenant** | Activer l'échange de clés hybride PQ partout (rétrocompatible, sans risque à déployer) |
| **2026–2028** | Inventorier tous les certificats et leur durée de vie ; raccourcir les durées de vie |
| **D'ici 2030** | RSA / ECDSA / ECDH **dépréciés** |
| **D'ici 2035** | RSA / ECDSA / ECDH **interdits**, y compris systèmes legacy (les modes hybrides survivent) |

---