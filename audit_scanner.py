#!/usr/bin/env python3
"""
audit_scanner.py — Mini-scanner d'audit de sécurité web, inspiré de la
méthodologie OWASP Top 10, exécuté contre `vulnerable_app.py` en local.

Ce script illustre en code la logique que réalisent des outils comme
OWASP ZAP / Burp Suite : cartographie des routes, tests de charge utile
(payloads) et vérification des en-têtes de sécurité HTTP, puis génération
d'un rapport priorisé par criticité.

⚠️ Usage strictement académique, contre une cible locale que vous contrôlez.

Prérequis : lancer d'abord `python3 vulnerable_app.py` dans un autre terminal.

Auteure : Oumaima Souguir — Master CDSI (UPHF)
"""

import json
import urllib.request
import urllib.parse
from datetime import datetime

TARGET = "http://127.0.0.1:5001"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 -- ", "admin'--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]


def http_get(path, params=None):
    url = TARGET + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "AuditScanner/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", errors="ignore")


def http_post(path, data):
    url = TARGET + path
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST",
                                  headers={"User-Agent": "AuditScanner/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", errors="ignore")


def check_security_headers():
    findings = []
    _, headers, _ = http_get("/")
    for h in SECURITY_HEADERS:
        if h not in headers:
            findings.append({
                "id": "A05-HEADERS",
                "title": f"En-tête de sécurité manquant : {h}",
                "severity": "Moyenne",
                "owasp": "A05:2021 – Mauvaise configuration de sécurité",
                "evidence": f"En-tête absent de la réponse HTTP de '/'",
            })
    return findings


def check_sql_injection():
    findings = []
    for payload in SQLI_PAYLOADS:
        status, _, body = http_post("/login", {"username": payload, "password": "x"})
        if "Bienvenue" in body:
            findings.append({
                "id": "A03-SQLI",
                "title": "Injection SQL dans le formulaire d'authentification (/login)",
                "severity": "Critique",
                "owasp": "A03:2021 – Injection",
                "evidence": f"Payload '{payload}' → authentification contournée : {body.strip()}",
            })
            break
    return findings


def check_xss():
    findings = []
    for payload in XSS_PAYLOADS:
        _, _, body = http_get("/search", {"q": payload})
        if payload in body:
            findings.append({
                "id": "A03-XSS",
                "title": "Cross-Site Scripting réfléchi (/search)",
                "severity": "Élevée",
                "owasp": "A03:2021 – Injection (XSS)",
                "evidence": f"Payload '{payload}' réfléchi tel quel dans la réponse HTML.",
            })
            break
    return findings


def check_access_control():
    findings = []
    status, _, body = http_get("/admin")
    if status == 200 and "administration" in body.lower():
        findings.append({
            "id": "A01-ACCESS",
            "title": "Panneau d'administration accessible sans authentification",
            "severity": "Critique",
            "owasp": "A01:2021 – Contrôle d'accès défaillant",
            "evidence": "GET /admin renvoie 200 sans session ni jeton d'authentification.",
        })
    return findings


SEVERITY_ORDER = {"Critique": 0, "Élevée": 1, "Moyenne": 2, "Faible": 3}


def generate_report(findings, output_path="audit_report_generated.md"):
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    lines = [
        "# Rapport d'audit de sécurité web — Méthodologie OWASP Top 10",
        "",
        f"**Cible :** {TARGET} (application de test locale)",
        f"**Date :** {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        f"**Nombre de vulnérabilités détectées :** {len(findings_sorted)}",
        "",
        "| Sévérité | Catégorie OWASP | Titre | Preuve |",
        "|---|---|---|---|",
    ]
    for f in findings_sorted:
        lines.append(f"| {f['severity']} | {f['owasp']} | {f['title']} | {f['evidence']} |")

    lines += [
        "",
        "## Recommandations priorisées",
        "",
        "1. **Requêtes préparées** : remplacer la concaténation SQL par des requêtes "
        "paramétrées (`?`, `cursor.execute(query, params)`).",
        "2. **Échappement systématique** des sorties HTML (`markupsafe.escape` / moteur "
        "de template Jinja2 en mode autoescape).",
        "3. **Contrôle d'accès** : exiger une session authentifiée et une vérification de "
        "rôle avant toute route sensible (`/admin`).",
        "4. **En-têtes de sécurité** : ajouter CSP, X-Frame-Options, X-Content-Type-Options, "
        "HSTS via un middleware (ex. `flask-talisman`).",
        "5. Désactiver le mode `debug` en production.",
        "",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return output_path


def main():
    print(f"[*] Audit de sécurité de {TARGET} — démarrage...")
    findings = []
    for check in (check_security_headers, check_sql_injection, check_xss, check_access_control):
        try:
            findings.extend(check())
        except Exception as e:
            print(f"[!] Erreur pendant {check.__name__}: {e}")
            print("    → Assurez-vous que 'vulnerable_app.py' tourne bien sur le port 5001.")
            return
    report_path = generate_report(findings)
    print(f"[+] {len(findings)} vulnérabilité(s) détectée(s).")
    print(f"[+] Rapport généré : {report_path}")
    print(json.dumps(findings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
