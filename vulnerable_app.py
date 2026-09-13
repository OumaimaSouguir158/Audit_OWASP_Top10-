#!/usr/bin/env python3
"""
vulnerable_app.py — Application web VOLONTAIREMENT VULNÉRABLE, à des fins
strictement pédagogiques et académiques (à la manière d'OWASP Juice Shop /
DVWA), utilisée comme cible locale pour le script d'audit `audit_scanner.py`.

⚠️ NE JAMAIS déployer cette application sur un réseau public ou en production.
Elle contient intentionnellement plusieurs vulnérabilités du OWASP Top 10 :
  - A03:2021 Injection (SQL)
  - A03:2021 Injection (XSS reflété)
  - A07:2021 Identification et authentification de mauvaise qualité
  - A05:2021 Mauvaise configuration de sécurité (en-têtes manquants, debug)

Auteure : Oumaima Souguir — Master CDSI (UPHF)
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = True  # (vulnérable) mode debug actif → fuite d'informations

DB_PATH = "vulnerable_app.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # (vulnérable) mots de passe stockés en clair
    cur.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [("admin", "admin123"), ("oumaima", "motdepasse"), ("guest", "guest")],
    )
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return "<h1>Vulnerable App — cible pédagogique d'audit OWASP</h1>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <form method="POST">
            Utilisateur: <input name="username"><br>
            Mot de passe: <input name="password" type="password"><br>
            <input type="submit">
        </form>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- (VULNÉRABLE — A03 Injection SQL) concaténation directe non paramétrée ---
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()

    if row:
        return f"Bienvenue {username} ! (id={row[0]})"
    return "Échec de connexion."


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # --- (VULNÉRABLE — A03 XSS réfléchi) injection directe de l'entrée utilisateur dans le HTML ---
    return f"<html><body>Résultats pour : {q}</body></html>"


@app.route("/admin")
def admin():
    # --- (VULNÉRABLE — A01 Contrôle d'accès défaillant) aucune vérification de session/rôle ---
    return "Panneau d'administration — accès non protégé !"


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001)
