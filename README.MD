<svg viewBox="0 0 1200 400" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#020603"/>
      <stop offset="100%" stop-color="#050f07"/>
    </linearGradient>
    <linearGradient id="chrome" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#c7ffd8"/>
      <stop offset="45%" stop-color="#3dff7a"/>
      <stop offset="100%" stop-color="#0a5c26"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%" cy="50%" r="60%">
      <stop offset="0%" stop-color="#00ff66" stop-opacity="0.30"/>
      <stop offset="100%" stop-color="#00ff66" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="lockGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#7dffb0"/>
      <stop offset="100%" stop-color="#00c94d"/>
    </linearGradient>
  </defs>

  <rect width="1200" height="400" fill="url(#bg)"/>
  <circle cx="220" cy="200" r="260" fill="url(#glow)"/>

  <!-- matrix-style falling code columns, faint -->
  <g font-family="'Consolas','Courier New',monospace" font-size="16" fill="#0f5c2c" opacity="0.55">
    <text x="40" y="40">01</text><text x="40" y="60">10</text><text x="40" y="80">11</text>
    <text x="40" y="100">00</text><text x="40" y="120">01</text><text x="40" y="140">10</text>
    <text x="80" y="60">10</text><text x="80" y="90">01</text><text x="80" y="120">11</text>
    <text x="80" y="150">00</text><text x="80" y="180">01</text>
    <text x="960" y="50">10</text><text x="960" y="75">01</text><text x="960" y="100">00</text>
    <text x="960" y="125">11</text><text x="960" y="150">10</text><text x="960" y="175">01</text>
    <text x="1010" y="70">01</text><text x="1010" y="100">11</text><text x="1010" y="130">00</text>
    <text x="1010" y="160">10</text><text x="1010" y="190">01</text>
    <text x="1080" y="40">00</text><text x="1080" y="65">10</text><text x="1080" y="90">01</text>
    <text x="1080" y="115">11</text><text x="1080" y="140">01</text><text x="1080" y="165">10</text>
    <text x="1140" y="55">11</text><text x="1140" y="85">00</text><text x="1140" y="115">01</text>
    <text x="1140" y="145">10</text><text x="1140" y="175">11</text>
    <text x="1150" y="240">01</text><text x="1150" y="265">10</text><text x="1150" y="290">00</text>
    <text x="1150" y="315">01</text><text x="1150" y="340">11</text>
    <text x="60" y="230">11</text><text x="60" y="255">01</text><text x="60" y="280">10</text>
    <text x="60" y="305">00</text><text x="60" y="330">01</text><text x="60" y="355">10</text>
  </g>

  <!-- orbiting qubit rings around the lock -->
  <g transform="translate(190,200)" fill="none" stroke="#12c95a" stroke-width="1.5" opacity="0.55">
    <ellipse rx="120" ry="46" transform="rotate(18)"/>
    <ellipse rx="120" ry="46" transform="rotate(78)"/>
    <ellipse rx="120" ry="46" transform="rotate(138)"/>
  </g>
  <g fill="#7dffb0">
    <circle cx="304" cy="172" r="5"/>
    <circle cx="102" cy="252" r="4"/>
    <circle cx="238" cy="298" r="4.5"/>
  </g>

  <!-- shield/lock mark -->
  <g transform="translate(190,200)">
    <path d="M0,-92 L78,-58 V18 C78,78 40,116 0,132 C-40,116 -78,78 -78,18 V-58 Z"
          fill="none" stroke="url(#chrome)" stroke-width="6" stroke-linejoin="round"/>
    <rect x="-34" y="-14" width="68" height="54" rx="10" fill="url(#lockGrad)"/>
    <path d="M-20,-14 v-18 a20,20 0 0 1 40,0 v18" fill="none" stroke="url(#chrome)" stroke-width="7" stroke-linecap="round"/>
    <circle cx="0" cy="12" r="7" fill="#020603"/>
    <rect x="-3" y="12" width="6" height="16" rx="2" fill="#020603"/>
  </g>

  <!-- wordmark -->
  <text x="420" y="188" font-family="'Segoe UI', Helvetica, Arial, sans-serif" font-weight="700" font-size="76" fill="url(#chrome)" letter-spacing="1">codequantum</text>
  <text x="424" y="232" font-family="'Segoe UI', Helvetica, Arial, sans-serif" font-weight="400" font-size="26" fill="#5fbf85" letter-spacing="3">POST-QUANTUM COMPATIBILITY SCANNER</text>

  <!-- clock chips: HNDL / Q-DAY -->
  <g font-family="'Segoe UI', Helvetica, Arial, sans-serif" font-weight="700" font-size="20">
    <rect x="424" y="264" width="146" height="42" rx="8" fill="none" stroke="#ff5d5d" stroke-width="2"/>
    <text x="497" y="291" fill="#ff5d5d" text-anchor="middle">HNDL</text>

    <rect x="588" y="264" width="146" height="42" rx="8" fill="none" stroke="#ffc95e" stroke-width="2"/>
    <text x="661" y="291" fill="#ffc95e" text-anchor="middle">Q-DAY</text>
  </g>
</svg>



<p align="center">
  <img src="banner.svg" alt="codequantum banner" width="100%">
</p>

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