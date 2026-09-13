# Rapport d'audit de sécurité web — Méthodologie OWASP Top 10

**Cible :** http://127.0.0.1:5001 (application de test locale)
**Date :** 12/09/2026 09:31
**Nombre de vulnérabilités détectées :** 7

| Sévérité | Catégorie OWASP | Titre | Preuve |
|---|---|---|---|
| Critique | A03:2021 – Injection | Injection SQL dans le formulaire d'authentification (/login) | Payload '' OR 1=1 -- ' → authentification contournée : Bienvenue ' OR 1=1 --  ! (id=1) |
| Critique | A01:2021 – Contrôle d'accès défaillant | Panneau d'administration accessible sans authentification | GET /admin renvoie 200 sans session ni jeton d'authentification. |
| Élevée | A03:2021 – Injection (XSS) | Cross-Site Scripting réfléchi (/search) | Payload '<script>alert(1)</script>' réfléchi tel quel dans la réponse HTML. |
| Moyenne | A05:2021 – Mauvaise configuration de sécurité | En-tête de sécurité manquant : Content-Security-Policy | En-tête absent de la réponse HTTP de '/' |
| Moyenne | A05:2021 – Mauvaise configuration de sécurité | En-tête de sécurité manquant : X-Frame-Options | En-tête absent de la réponse HTTP de '/' |
| Moyenne | A05:2021 – Mauvaise configuration de sécurité | En-tête de sécurité manquant : X-Content-Type-Options | En-tête absent de la réponse HTTP de '/' |
| Moyenne | A05:2021 – Mauvaise configuration de sécurité | En-tête de sécurité manquant : Strict-Transport-Security | En-tête absent de la réponse HTTP de '/' |

## Recommandations priorisées

1. **Requêtes préparées** : remplacer la concaténation SQL par des requêtes paramétrées (`?`, `cursor.execute(query, params)`).
2. **Échappement systématique** des sorties HTML (`markupsafe.escape` / moteur de template Jinja2 en mode autoescape).
3. **Contrôle d'accès** : exiger une session authentifiée et une vérification de rôle avant toute route sensible (`/admin`).
4. **En-têtes de sécurité** : ajouter CSP, X-Frame-Options, X-Content-Type-Options, HSTS via un middleware (ex. `flask-talisman`).
5. Désactiver le mode `debug` en production.
