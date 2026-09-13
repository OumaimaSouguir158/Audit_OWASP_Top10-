# Projet 2 — Audit de sécurité d'une application web selon l'OWASP Top 10
## Objectif
Réaliser un audit de sécurité complet d'une application web volontairement
vulnérable, en suivant la méthodologie OWASP.

## Contenu
```
vulnerable_app.py          → application Flask volontairement vulnérable (cible de test locale)
audit_scanner.py           → scanner d'audit : cartographie + tests de payloads + en-têtes HTTP
audit_report_generated.md  → exemple de rapport généré automatiquement
requirements.txt
```

## Comment l'exécuter
```bash
pip install -r requirements.txt
python3 vulnerable_app.py &          # lance la cible sur http://127.0.0.1:5001
python3 audit_scanner.py             # exécute l'audit et génère le rapport
```

## Vulnérabilités volontairement introduites (cible d'audit)
| Catégorie OWASP Top 10 (2021) | Vulnérabilité | Route |
|---|---|---|
| A01 – Contrôle d'accès défaillant | Panneau admin sans authentification | `/admin` |
| A03 – Injection | Injection SQL (authentification contournable) | `/login` |
| A03 – Injection | XSS réfléchi | `/search` |
| A05 – Mauvaise configuration | En-têtes de sécurité manquants, mode debug actif | global |

## Méthodologie suivie
1. **Reconnaissance** : cartographie des routes exposées.
2. **Tests actifs** : injection de payloads SQLi/XSS connus, vérification des
   réponses (contournement d'authentification, réflexion non échappée).
3. **Analyse de configuration** : vérification des en-têtes de sécurité HTTP.
4. **Rapport priorisé** : classement des vulnérabilités par sévérité
   (Critique > Élevée > Moyenne) avec preuve et recommandation.

En conditions réelles, ce même travail est réalisé avec **OWASP ZAP** ou
**Burp Suite (édition communautaire)** contre une cible comme *OWASP Juice
Shop* ou *DVWA* ; `audit_scanner.py` reproduit ici la logique de ces outils
en code Python afin de documenter la méthodologie de bout en bout.

## Ce que ça démontre au jury
Capacité à mener un audit structuré et documenté — compétence directement
employable en cabinet de conseil sécurité.
