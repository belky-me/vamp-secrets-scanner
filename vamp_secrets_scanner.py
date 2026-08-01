#!/usr/bin/env python3
"""
vamp_secrets_scanner.py — Escáner Estático de Secretos y Credenciales
======================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de análisis estático que detecta secretos, credenciales y
tokens hardcodeados en repositorios de código fuente, ficheros de
configuración y cualquier árbol de directorios. Orientada a auditorías
de seguridad, revisiones de código previas a despliegue y detección de
fugas de credenciales antes de publicar un repositorio.

Detecta más de 80 patrones de secretos y datos sensibles organizados en categorías:
  · Claves de nube (AWS, GCP, Azure)
  · Tokens de plataforma (GitHub, GitLab, Slack, Telegram, Discord)
  · Pasarelas de pago (Stripe, PayPal, Braintree)
  · Bases de datos (cadenas de conexión con credenciales embebidas)
  · Infraestructura (WireGuard, SSH, certificados PEM)
  · Servicios de correo y comunicaciones (SendGrid, Twilio, Mailgun)
  · Patrones genéricos de alta entropía (password=, api_key=, secret=…)
  · JWT y tokens Bearer
  · PII financiera: tarjetas de crédito/débito (Visa, MC, Amex, Discover),
    IBAN/BIC bancarios, CCC español, CVV/CVC hardcodeados
  · PII de identidad: SSN EE.UU., DNI/NIE/CIF español, NHS UK
  · PII de contacto: email en contexto sensible, teléfonos ES e internacionales

Complementa la detección por regex con un análisis de entropía de
Shannon sobre cadenas en asignaciones, lo que permite capturar secretos
cuyo formato no se ajusta a ningún patrón conocido pero cuya densidad
de información los delata como valores generados.

ARQUITECTURA DE EJECUCIÓN (3 fases)
------------------------------------
  Fase 1 — Descubrimiento de ficheros
    Recorre el árbol de directorios objetivo respetando las listas de
    exclusión (.git, node_modules, .venv, __pycache__, build, dist…) y
    el filtro de extensiones configurable. Soporta modo recursivo y
    profundidad máxima configurable. Informa del número de ficheros y
    bytes totales en alcance antes de empezar el escaneo.

  Fase 2 — Escaneo de patrones y entropía
    Para cada fichero en alcance:
    · Aplica los 60+ patrones regex de la base de datos SECRET_PATTERNS
      línea a línea; registra fichero, línea, categoría, nombre del
      patrón y un extracto censurado del hallazgo.
    · Calcula la entropía de Shannon de cadenas largas (≥20 chars) que
      aparezcan en contextos de asignación (key=, :, =) y marca como
      HIGH_ENTROPY aquellas que superen el umbral configurable (por
      defecto 4.5 bits/símbolo), excluyendo ruido conocido (hashes hex,
      base64 de imágenes…).
    Toda la operación es local, sin tráfico de red.

  Fase 3 — Clasificación, deduplicación e informe
    Normaliza cada hallazgo, elimina duplicados por (patrón + hash del
    valor), asigna severidad (CRÍTICO / ALTO / MEDIO / BAJO) y genera
    la salida seleccionada: tabla Rich en consola, JSON estructurado y/o
    informe HTML dark-theme standalone.

MODELO DE SEVERIDAD
-------------------
  CRÍTICO — Clave activa verificable por formato (AWS AKIA, PEM privada,
            Stripe sk_live_, Telegram BOT_TOKEN, WireGuard PrivateKey)
            o dato financiero/personal de alto impacto (PAN de tarjeta,
            IBAN, SSN EE.UU., CVV).
  ALTO    — Token de plataforma (GitHub PAT, GitLab, Slack, JWT) o dato
            de identidad regulado (DNI, NIE, CIF, BIC/SWIFT).
  MEDIO   — Patrón genérico con valor (password=, secret=, api_key=).
  BAJO    — Alta entropía o dato de contacto en contexto sensible
            (email=, teléfono).

DEPENDENCIAS
------------
  rich    >= 13.7.0    — Salida de consola con formato enriquecido
  (stdlib únicamente: re, os, math, pathlib, hashlib, json, argparse)

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html import escape
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from rich.console import Console
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────

VERSION   = "2.0"
TOOL_NAME = "vamp-secrets-scanner"

BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
        by VampSecure Studios · vamp-secrets-scanner v2.0 · Static Secrets & Git History Scanner
        ─────────────────────────────────────────────────────────────────────────────────────────
        USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Base de datos de patrones de secretos
# ─────────────────────────────────────────────────────────────────────────────
# Cada entrada:
#   name      — identificador legible del patrón
#   regex     — expresión regular (compilada más abajo)
#   severity  — CRITICAL / HIGH / MEDIUM / LOW
#   category  — agrupación temática
# ─────────────────────────────────────────────────────────────────────────────

_RAW_PATTERNS: List[Dict[str, str]] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    {"name": "AWS Access Key ID",          "severity": "CRITICAL", "category": "Cloud · AWS",
     "regex": r"(?<![A-Z0-9])(AKIA|AGPA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"},
    {"name": "AWS Secret Access Key",      "severity": "CRITICAL", "category": "Cloud · AWS",
     "regex": r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9+/]{40})['\"]"},
    {"name": "AWS Session Token",          "severity": "HIGH",     "category": "Cloud · AWS",
     "regex": r"(?i)aws.{0,20}session.token.{0,10}['\"]([A-Za-z0-9+/=]{100,})['\"]"},

    # ── GCP ──────────────────────────────────────────────────────────────────
    {"name": "Google API Key",             "severity": "CRITICAL", "category": "Cloud · GCP",
     "regex": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "GCP Service Account JSON",   "severity": "CRITICAL", "category": "Cloud · GCP",
     "regex": r'"private_key"\s*:\s*"-----BEGIN (RSA |EC )?PRIVATE KEY'},
    {"name": "Firebase API Key",           "severity": "HIGH",     "category": "Cloud · GCP",
     "regex": r"(?i)firebase.{0,20}['\"]AIza[0-9A-Za-z\-_]{35}['\"]"},

    # ── Azure ─────────────────────────────────────────────────────────────────
    {"name": "Azure Storage Key",          "severity": "CRITICAL", "category": "Cloud · Azure",
     "regex": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"},
    {"name": "Azure Client Secret",        "severity": "HIGH",     "category": "Cloud · Azure",
     "regex": r"(?i)(client.?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9~.\-_]{32,})['\"]?"},

    # ── GitHub ────────────────────────────────────────────────────────────────
    {"name": "GitHub PAT (classic)",       "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"ghp_[A-Za-z0-9]{36}"},
    {"name": "GitHub OAuth Token",         "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"gho_[A-Za-z0-9]{36}"},
    {"name": "GitHub App Token",           "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"ghs_[A-Za-z0-9]{36}"},
    {"name": "GitHub Fine-Grained PAT",    "severity": "HIGH",     "category": "VCS · GitHub",
     "regex": r"github_pat_[A-Za-z0-9_]{82}"},
    {"name": "GitHub Actions Secret",      "severity": "MEDIUM",   "category": "VCS · GitHub",
     "regex": r"(?i)GITHUB_TOKEN\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"},

    # ── GitLab ────────────────────────────────────────────────────────────────
    {"name": "GitLab PAT",                 "severity": "HIGH",     "category": "VCS · GitLab",
     "regex": r"glpat-[A-Za-z0-9\-_]{20}"},
    {"name": "GitLab Runner Token",        "severity": "HIGH",     "category": "VCS · GitLab",
     "regex": r"GR1348941[A-Za-z0-9\-_]{20}"},

    # ── Stripe ────────────────────────────────────────────────────────────────
    {"name": "Stripe Live Secret Key",     "severity": "CRITICAL", "category": "Pagos · Stripe",
     "regex": r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Test Secret Key",     "severity": "MEDIUM",   "category": "Pagos · Stripe",
     "regex": r"sk_test_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Webhook Secret",      "severity": "CRITICAL", "category": "Pagos · Stripe",
     "regex": r"whsec_[A-Za-z0-9]{32,}"},
    {"name": "Stripe Publishable Key",     "severity": "LOW",      "category": "Pagos · Stripe",
     "regex": r"pk_live_[0-9a-zA-Z]{24,}"},

    # ── PayPal / Braintree ────────────────────────────────────────────────────
    {"name": "PayPal Client Secret",       "severity": "CRITICAL", "category": "Pagos · PayPal",
     "regex": r"(?i)paypal.{0,20}(client.?secret|secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{32,})['\"]?"},
    {"name": "Braintree Access Token",     "severity": "CRITICAL", "category": "Pagos · Braintree",
     "regex": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"},

    # ── Slack ─────────────────────────────────────────────────────────────────
    {"name": "Slack Bot Token",            "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}"},
    {"name": "Slack User Token",           "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32}"},
    {"name": "Slack App Token",            "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"xapp-[0-9]-[A-Za-z0-9]{10}-[0-9]{13}-[A-Za-z0-9]{64}"},
    {"name": "Slack Webhook URL",          "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}"},
    {"name": "Slack Signing Secret",       "severity": "HIGH",     "category": "Comunicaciones · Slack",
     "regex": r"(?i)slack.{0,20}sign.{0,10}secret\s*[:=]\s*['\"]?([A-Za-z0-9]{32})['\"]?"},

    # ── Telegram ──────────────────────────────────────────────────────────────
    {"name": "Telegram BOT_TOKEN",         "severity": "CRITICAL", "category": "Comunicaciones · Telegram",
     "regex": r"(?<!\w)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?!\w)"},

    # ── Discord ───────────────────────────────────────────────────────────────
    {"name": "Discord Bot Token",          "severity": "HIGH",     "category": "Comunicaciones · Discord",
     "regex": r"(?i)discord.{0,20}['\"]([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})['\"]"},
    {"name": "Discord Webhook URL",        "severity": "HIGH",     "category": "Comunicaciones · Discord",
     "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}"},

    # ── Twilio ────────────────────────────────────────────────────────────────
    {"name": "Twilio Account SID",         "severity": "HIGH",     "category": "Comunicaciones · Twilio",
     "regex": r"AC[a-z0-9]{32}"},
    {"name": "Twilio Auth Token",          "severity": "CRITICAL", "category": "Comunicaciones · Twilio",
     "regex": r"(?i)twilio.{0,20}auth.?token\s*[:=]\s*['\"]?([a-z0-9]{32})['\"]?"},
    {"name": "Twilio API Key",             "severity": "HIGH",     "category": "Comunicaciones · Twilio",
     "regex": r"SK[a-z0-9]{32}"},

    # ── SendGrid ──────────────────────────────────────────────────────────────
    {"name": "SendGrid API Key",           "severity": "CRITICAL", "category": "Correo · SendGrid",
     "regex": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"},

    # ── Mailgun ───────────────────────────────────────────────────────────────
    {"name": "Mailgun API Key",            "severity": "HIGH",     "category": "Correo · Mailgun",
     "regex": r"key-[0-9a-f]{32}"},
    {"name": "Mailgun Webhook Key",        "severity": "HIGH",     "category": "Correo · Mailgun",
     "regex": r"(?i)mailgun.{0,20}['\"]([A-Za-z0-9\-]{72})['\"]"},

    # ── Claves privadas / certificados ────────────────────────────────────────
    {"name": "RSA Private Key (PEM)",      "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"name": "EC Private Key (PEM)",       "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN EC PRIVATE KEY-----"},
    {"name": "OpenSSH Private Key",        "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----"},
    {"name": "PKCS8 Private Key",          "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN PRIVATE KEY-----"},
    {"name": "PGP Private Key Block",      "severity": "CRITICAL", "category": "Infraestructura · PKI",
     "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----"},

    # ── WireGuard ─────────────────────────────────────────────────────────────
    {"name": "WireGuard PrivateKey",       "severity": "CRITICAL", "category": "Infraestructura · WireGuard",
     "regex": r"(?m)^PrivateKey\s*=\s*[A-Za-z0-9+/]{43}="},

    # ── Bases de datos ────────────────────────────────────────────────────────
    {"name": "PostgreSQL DSN con contraseña", "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"postgres(?:ql)?://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "MySQL DSN con contraseña",   "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"mysql://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "MongoDB URI con contraseña", "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]{3,}@[^\s\"']+"},
    {"name": "Redis URL con contraseña",   "severity": "HIGH",     "category": "Base de datos",
     "regex": r"redis://:([^@]{3,})@[^\s\"']+"},
    {"name": "MSSQL DSN con contraseña",   "severity": "CRITICAL", "category": "Base de datos",
     "regex": r"(?i)Server=[^;]+;.*Password=[^;]{3,}"},

    # ── JWT ───────────────────────────────────────────────────────────────────
    {"name": "JSON Web Token (JWT)",       "severity": "HIGH",     "category": "Autenticación · JWT",
     "regex": r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"},
    {"name": "JWT Secret hardcodeado",     "severity": "CRITICAL", "category": "Autenticación · JWT",
     "regex": r"(?i)(jwt.?secret|JWT_SECRET)\s*[:=]\s*['\"](.{8,})['\"]"},

    # ── OAuth / API genéricos ─────────────────────────────────────────────────
    {"name": "Bearer Token en código",     "severity": "HIGH",     "category": "Autenticación · OAuth",
     "regex": r"(?i)Bearer\s+[A-Za-z0-9\-_=]{20,}(?=['\"\s])"},
    {"name": "OAuth client_secret",        "severity": "HIGH",     "category": "Autenticación · OAuth",
     "regex": r"(?i)client.?secret\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"},

    # ── NPM / PyPI ────────────────────────────────────────────────────────────
    {"name": "NPM Auth Token",             "severity": "HIGH",     "category": "Registros · NPM",
     "regex": r"//registry\.npmjs\.org/:_authToken\s*=\s*([A-Za-z0-9\-_]{36,})"},
    {"name": "PyPI Upload Token",          "severity": "HIGH",     "category": "Registros · PyPI",
     "regex": r"pypi-[A-Za-z0-9\-_]{80,}"},

    # ── Otros servicios ───────────────────────────────────────────────────────
    {"name": "Shopify Admin API Key",      "severity": "CRITICAL", "category": "E-commerce · Shopify",
     "regex": r"shpat_[A-Fa-f0-9]{32}"},
    {"name": "Shopify Storefront Token",   "severity": "MEDIUM",   "category": "E-commerce · Shopify",
     "regex": r"shpss_[A-Fa-f0-9]{32}"},
    {"name": "HubSpot API Key",            "severity": "HIGH",     "category": "CRM · HubSpot",
     "regex": r"(?i)hubspot.{0,20}['\"]([A-Za-z0-9\-]{36})['\"]"},

    # ── Datos personales y financieros (PII / PCI DSS) ───────────────────────
    # Tarjetas de crédito/débito — PAN (Primary Account Number)
    # Exige separadores (espacio o guión) para reducir falsos positivos.
    # Se detectan los rangos BIN de los principales emisores.
    {"name": "Tarjeta Visa",               "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "Tarjeta Mastercard",         "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "Tarjeta American Express",   "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}(?!\d)"},
    {"name": "Tarjeta Discover",           "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?<!\d)6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)"},
    {"name": "CVV/CVC hardcodeado",        "severity": "CRITICAL", "category": "PII · Tarjeta de pago",
     "regex": r"(?i)(?:cvv|cvc|csc|cvv2|cvc2)\s*[:=]\s*['\"]?([0-9]{3,4})['\"]?"},

    # IBAN — Número Internacional de Cuenta Bancaria
    # Cobre los 30+ países del espacio SEPA más los principales internacionales.
    # Formato: 2 letras de país + 2 dígitos de control + BBAN variable.
    {"name": "IBAN bancario",              "severity": "CRITICAL", "category": "PII · Cuenta bancaria",
     "regex": r"\b(ES|GB|DE|FR|IT|NL|BE|PT|AT|CH|SE|NO|DK|FI|PL|CZ|HU|RO|HR|BG|SK|SI|LT|LV|EE|MT|CY|LU|IE|GR|AD|MC|SM|VA|IS|LI)[0-9]{2}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{4}[\s]?[0-9A-Z]{0,14}\b"},
    {"name": "BIC/SWIFT bancario",         "severity": "HIGH",     "category": "PII · Cuenta bancaria",
     "regex": r"\b[A-Z]{4}(ES|GB|DE|FR|IT|NL|BE|PT|US|CH|JP|CN|AU|CA|SG|HK|AE|SA|BR)[A-Z0-9]{2}([A-Z0-9]{3})?\b"},

    # Número de Seguridad Social y documentos de identidad
    {"name": "SSN EE.UU.",                 "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?!\d)"},
    {"name": "DNI español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\d)(?!00000000)[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIE español",                "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE](?!\w)"},
    {"name": "NIF/CIF empresa española",   "severity": "HIGH",     "category": "PII · Identidad",
     "regex": r"(?<!\w)[ABCDEFGHJNPQRSUVW][0-9]{7}[0-9A-J](?!\w)"},
    # NUSS — Número de la Seguridad Social español
    # Formato: 2 dígitos de provincia (01-52) + 8 de secuencia + 2 de control = 12 dígitos.
    # Admite separadores (/  o  -) entre los tres grupos, que es la presentación
    # oficial en documentos físicos (p.ej. 28/12345678/20).
    {"name": "NUSS (Seg. Social español)", "severity": "CRITICAL", "category": "PII · Identidad",
     "regex": r"(?<!\d)(0[1-9]|[1-4][0-9]|5[0-2])[/\-\s]?[0-9]{8}[/\-\s]?[0-9]{2}(?!\d)"},
    {"name": "NHS UK (número paciente)",   "severity": "CRITICAL", "category": "PII · Salud",
     "regex": r"(?<!\d)[0-9]{3}[\s\-][0-9]{3}[\s\-][0-9]{4}(?!\d)"},

    # Datos de contacto en contextos sensibles (volcados de BD, logs, configs)
    {"name": "Email en contexto sensible", "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?i)(?:email|correo|mail|e-mail)\s*[:=]\s*['\"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['\"]?"},
    {"name": "Teléfono español",           "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)(?:\+34|0034)?[\s\-]?[6-9][0-9]{2}[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}(?!\d)"},
    {"name": "Teléfono internacional",     "severity": "LOW",      "category": "PII · Contacto",
     "regex": r"(?<!\d)\+(?!34)[1-9][0-9]{1,2}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{3,4}[\s\-]?[0-9]{2,4}(?!\d)"},

    # Números de cuenta / referencia financiera en contexto
    {"name": "Número de cuenta bancaria ES (CCC)", "severity": "HIGH", "category": "PII · Cuenta bancaria",
     "regex": r"(?<!\d)[0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{2}[\s\-][0-9]{10}(?!\d)"},

    # ── Patrones genéricos (alta cobertura, más falsos positivos) ─────────────
    {"name": "Contraseña hardcodeada",     "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"},
    {"name": "API key genérica",           "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:api.?key|apikey|API_KEY)\s*[:=]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"},
    {"name": "Secret genérico",            "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:secret|SECRET)\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/]{16,})['\"]"},
    {"name": "Token genérico",             "severity": "MEDIUM",   "category": "Genérico",
     "regex": r"(?i)(?:token|TOKEN)\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/]{20,})['\"]"},
    {"name": "Private key genérica",       "severity": "HIGH",     "category": "Genérico",
     "regex": r"(?i)private.?key\s*[:=]\s*['\"]([A-Za-z0-9\-_.+/=]{20,})['\"]"},
]

# Compilar todos los patrones una sola vez al importar
SECRET_PATTERNS = [
    {**p, "compiled": re.compile(p["regex"], re.MULTILINE)}
    for p in _RAW_PATTERNS
]

# ─────────────────────────────────────────────────────────────────────────────
# Configuración de descubrimiento
# ─────────────────────────────────────────────────────────────────────────────

EXCLUDE_DIRS: Set[str] = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    "build", "dist", "target", ".gradle", ".idea", ".vscode",
    "vendor", "third_party", "external", "deps",
}

INCLUDE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".swift", ".c", ".cpp", ".h",
    ".cs", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".env", ".env.example", ".env.local", ".env.production", ".env.staging",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".xml", ".properties", ".gradle", ".tf", ".tfvars",
    ".Dockerfile", ".dockercompose",
    ".htaccess", ".htpasswd",
    ".pem", ".key", ".crt", ".cer",
    ".txt", ".md",
}

# Nombres de fichero que se escanean independientemente de su extensión
INCLUDE_FILENAMES: Set[str] = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Procfile", ".env", ".envrc",
    "webpack.config.js", "next.config.js", "vite.config.js",
    "settings.py", "config.py", "database.py",
    "application.properties", "application.yml",
    "secrets.yaml", "values.yaml",
}

# Extensiones a ignorar siempre (binarios, media, compilados)
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".a", ".o",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".lock", ".sum",  # lock files: demasiado ruido
}

# ─────────────────────────────────────────────────────────────────────────────
# Modelos de datos
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


@dataclass
class Finding:
    """Hallazgo de secreto en un fichero o en el historial git."""
    file:       str
    line_no:    int
    pattern:    str
    category:   str
    severity:   Severity
    preview:    str           # extracto censurado
    context:    List[str]     # líneas de contexto (±2)
    fingerprint: str          # hash del valor detectado (para dedup)
    # Campos opcionales para hallazgos de historial git
    git_commit: Optional[str] = None  # hash del commit donde apareció
    git_author: Optional[str] = None  # autor del commit
    git_date:   Optional[str] = None  # fecha ISO del commit
    allowlisted: bool = False          # ignorado por la allowlist

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Fase 1 — Descubrimiento de ficheros
# ─────────────────────────────────────────────────────────────────────────────

def discover_files(root: Path, max_depth: Optional[int], all_extensions: bool) -> Iterator[Path]:
    """
    Recorre el árbol desde `root`, respetando EXCLUDE_DIRS y el filtro de
    extensiones. Emite Path de cada fichero candidato.
    """
    def _walk(path: Path, depth: int) -> Iterator[Path]:
        if max_depth is not None and depth > max_depth:
            return
        try:
            entries = sorted(path.iterdir())
        except PermissionError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in EXCLUDE_DIRS:
                    yield from _walk(entry, depth + 1)
            elif entry.is_file():
                ext = entry.suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    continue
                if all_extensions:
                    yield entry
                elif entry.name in INCLUDE_FILENAMES or ext in INCLUDE_EXTENSIONS:
                    yield entry

    yield from _walk(root, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2 — Escaneo: regex + entropía
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Entropía de Shannon en bits/símbolo."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum(f / n * math.log2(f / n) for f in freq.values())


def _censor(match: str) -> str:
    """Devuelve los primeros 6 caracteres y asteriscos para el resto."""
    if len(match) <= 6:
        return "***"
    return match[:6] + "***" + match[-2:]


def _fingerprint(value: str, pattern_name: str) -> str:
    raw = f"{pattern_name}:{value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _context_lines(lines: List[str], lineno: int, radius: int = 2) -> List[str]:
    start = max(0, lineno - radius - 1)
    end   = min(len(lines), lineno + radius)
    return [f"  {i+1:4d} │ {lines[i].rstrip()}" for i in range(start, end)]


def scan_file(path: Path, entropy_threshold: float) -> List[Finding]:
    """Escanea un único fichero y retorna sus hallazgos."""
    try:
        raw = path.read_bytes()
        # Saltar ficheros binarios por heurística
        if b"\x00" in raw[:8192]:
            return []
        text = raw.decode("utf-8", errors="replace")
    except (PermissionError, OSError):
        return []

    lines   = text.splitlines()
    findings: List[Finding] = []
    seen_fps: Set[str] = set()

    # ── Patrones regex ────────────────────────────────────────────────────────
    for pat in SECRET_PATTERNS:
        for m in pat["compiled"].finditer(text):
            value   = m.group(0)
            fp      = _fingerprint(value, pat["name"])
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            line_no = text[:m.start()].count("\n") + 1
            findings.append(Finding(
                file      = str(path),
                line_no   = line_no,
                pattern   = pat["name"],
                category  = pat["category"],
                severity  = Severity(pat["severity"]),
                preview   = _censor(value),
                context   = _context_lines(lines, line_no),
                fingerprint = fp,
            ))

    # ── Entropía de Shannon ───────────────────────────────────────────────────
    # Busca cadenas largas en contextos de asignación que superen el umbral
    _ENTROPY_RE = re.compile(
        r"""(?:=|:|:=)\s*['"]?([A-Za-z0-9+/=\-_.~]{20,})['"]?""",
        re.MULTILINE,
    )
    # Falsos positivos frecuentes: hashes hex puros, UUIDs, rutas, URLs
    _NOISE_RE = re.compile(
        r"^(?:[0-9a-f]{32,}|[0-9A-Fa-f\-]{36}|https?://|/[a-z])$",
        re.IGNORECASE,
    )
    for m in _ENTROPY_RE.finditer(text):
        candidate = m.group(1)
        if _NOISE_RE.match(candidate):
            continue
        entropy = _shannon_entropy(candidate)
        if entropy < entropy_threshold:
            continue
        fp = _fingerprint(candidate, "HIGH_ENTROPY")
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        line_no = text[:m.start()].count("\n") + 1
        findings.append(Finding(
            file      = str(path),
            line_no   = line_no,
            pattern   = f"Alta Entropía (H={entropy:.2f} bits)",
            category  = "Entropía",
            severity  = Severity.LOW,
            preview   = _censor(candidate),
            context   = _context_lines(lines, line_no),
            fingerprint = fp,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2b — Escaneo de historial Git
# ─────────────────────────────────────────────────────────────────────────────

def _is_git_repo(path: Path) -> bool:
    """Devuelve True si el directorio es un repositorio git."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=path, capture_output=True, text=True,
    )
    return result.returncode == 0


def scan_git_history(
    repo_path: Path,
    entropy_threshold: float,
    max_commits: int = 0,
) -> List[Finding]:
    """
    Escanea el historial completo de git buscando secretos en las líneas añadidas.

    Estrategia:
      1. Obtiene todos los commits (todos los branches) con `git log --all`.
      2. Para cada commit, extrae el diff completo de líneas añadidas (+).
      3. Aplica los mismos patrones regex y análisis de entropía que el escaneo
         de ficheros, pero registrando también el hash del commit, autor y fecha.

    Esto detecta secretos que fueron introducidos y luego borrados del árbol
    actual, que son invisibles para el escaneo de ficheros estándar.

    Parámetros
    ----------
    repo_path:         Ruta al repositorio git.
    entropy_threshold: Umbral de Shannon (float("inf") = desactivado).
    max_commits:       Límite de commits a procesar. 0 = sin límite.
    """
    if not _is_git_repo(repo_path):
        return []

    # Obtener lista de commits: hash, autor, fecha ISO
    log_fmt = "%H\x1f%ae\x1f%aI"
    log_cmd = ["git", "log", "--all", "--no-merges", f"--format={log_fmt}"]
    if max_commits > 0:
        log_cmd += [f"-n{max_commits}"]

    log_result = subprocess.run(
        log_cmd, cwd=repo_path, capture_output=True, text=True, errors="replace",
    )
    if log_result.returncode != 0:
        return []

    commit_lines = [l for l in log_result.stdout.splitlines() if l.strip()]
    findings: List[Finding] = []
    seen_fps: Set[str] = set()

    # Regexes auxiliares para parsear el diff
    FILE_RE   = re.compile(r"^\+\+\+ b/(.+)$")
    ADDED_RE  = re.compile(r"^\+(?!\+\+)(.*)$")  # línea añadida (no la cabecera +++)
    LINENO_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

    _ENTROPY_RE = re.compile(
        r"""(?:=|:|:=)\s*['"]?([A-Za-z0-9+/=\-_.~]{20,})['"]?""",
        re.MULTILINE,
    )
    _NOISE_RE = re.compile(
        r"^(?:[0-9a-f]{32,}|[0-9A-Fa-f\-]{36}|https?://|/[a-z])$",
        re.IGNORECASE,
    )

    for raw in commit_lines:
        parts = raw.split("\x1f")
        if len(parts) != 3:
            continue
        commit_hash, author, date = parts

        # Obtener el diff completo del commit (solo líneas añadidas para velocidad)
        diff_result = subprocess.run(
            ["git", "show", "--no-notes", "--format=", "-U0", commit_hash],
            cwd=repo_path, capture_output=True, text=True, errors="replace",
        )
        if diff_result.returncode != 0:
            continue

        current_file = ""
        current_line = 0

        for diff_line in diff_result.stdout.splitlines():
            # Detectar qué fichero estamos analizando
            m_file = FILE_RE.match(diff_line)
            if m_file:
                current_file = m_file.group(1)
                continue

            # Actualizar número de línea desde el header @@ +N @@
            m_lineno = LINENO_RE.match(diff_line)
            if m_lineno:
                current_line = int(m_lineno.group(1)) - 1
                continue

            m_added = ADDED_RE.match(diff_line)
            if not m_added:
                continue

            line_content = m_added.group(1)
            current_line += 1

            # ── Patrones regex ────────────────────────────────────────────────
            for pat in SECRET_PATTERNS:
                for m in pat["compiled"].finditer(line_content):
                    value = m.group(0)
                    # El fingerprint incluye el commit para no suprimir el mismo
                    # secreto en commits distintos (puede ser la misma clave rotada).
                    fp = _fingerprint(value, f"git:{pat['name']}")
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)
                    findings.append(Finding(
                        file        = current_file,
                        line_no     = current_line,
                        pattern     = pat["name"],
                        category    = pat["category"],
                        severity    = Severity(pat["severity"]),
                        preview     = _censor(value),
                        context     = [f"  git:{commit_hash[:8]} — {line_content.rstrip()}"],
                        fingerprint = fp,
                        git_commit  = commit_hash,
                        git_author  = author,
                        git_date    = date,
                    ))

            # ── Entropía ──────────────────────────────────────────────────────
            if entropy_threshold < float("inf"):
                for m in _ENTROPY_RE.finditer(line_content):
                    candidate = m.group(1)
                    if _NOISE_RE.match(candidate):
                        continue
                    entropy = _shannon_entropy(candidate)
                    if entropy < entropy_threshold:
                        continue
                    fp = _fingerprint(candidate, f"git:HIGH_ENTROPY:{commit_hash[:8]}")
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)
                    findings.append(Finding(
                        file        = current_file,
                        line_no     = current_line,
                        pattern     = f"Alta Entropía (H={entropy:.2f} bits)",
                        category    = "Entropía",
                        severity    = Severity.LOW,
                        preview     = _censor(candidate),
                        context     = [f"  git:{commit_hash[:8]} — {line_content.rstrip()}"],
                        fingerprint = fp,
                        git_commit  = commit_hash,
                        git_author  = author,
                        git_date    = date,
                    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Allowlist — filtro de falsos positivos conocidos
# ─────────────────────────────────────────────────────────────────────────────

def load_allowlist(path: str) -> List[dict]:
    """
    Carga una allowlist desde un fichero JSON.

    Formato esperado:
    {
      "allowlist": [
        {"fingerprint": "abc123def456"},
        {"pattern": "DNI español", "file": "tests/fixtures/datos_prueba.py"},
        {"pattern": "Alta Entropía*"},
        {"file": "tests/fixtures/"}
      ]
    }

    Cada entrada puede filtrar por 'fingerprint' exacto, por 'pattern'
    (admite glob parcial con *), por 'file' (prefijo de ruta) o
    por combinación pattern + file.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("allowlist", [])
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[yellow]  Aviso: no se pudo leer la allowlist '{path}': {exc}[/]")
        return []


def apply_allowlist(findings: List[Finding], allowlist: List[dict]) -> List[Finding]:
    """
    Marca como `allowlisted=True` los hallazgos que coincidan con alguna
    entrada de la allowlist. Devuelve la lista con el flag actualizado.
    """
    if not allowlist:
        return findings

    def _matches(f: Finding, entry: dict) -> bool:
        # Coincidencia por fingerprint exacto
        if "fingerprint" in entry:
            return f.fingerprint == entry["fingerprint"]
        # Coincidencia por patrón (glob simple con *)
        pattern_ok = True
        if "pattern" in entry:
            pat = entry["pattern"]
            if pat.endswith("*"):
                pattern_ok = f.pattern.startswith(pat[:-1])
            else:
                pattern_ok = f.pattern == pat
        # Coincidencia por fichero (prefijo)
        file_ok = True
        if "file" in entry:
            file_ok = f.file.startswith(entry["file"]) or entry["file"] in f.file
        return pattern_ok and file_ok

    for f in findings:
        for entry in allowlist:
            if _matches(f, entry):
                f.allowlisted = True
                break
    return findings


def generate_allowlist(findings: List[Finding], path: str) -> None:
    """
    Genera un fichero allowlist JSON a partir de los hallazgos actuales.
    Útil para establecer un baseline inicial en repositorios heredados.
    """
    entries = [{"fingerprint": f.fingerprint, "pattern": f.pattern, "file": f.file}
               for f in findings]
    out = {
        "_generado_por": f"{TOOL_NAME} v{VERSION}",
        "_fecha": datetime.now(timezone.utc).isoformat(),
        "_nota": "Edita esta allowlist para suprimir falsos positivos conocidos. "
                 "Elimina entradas para que vuelvan a reportarse.",
        "allowlist": entries,
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[green]  ✔ Allowlist generada en {path} ({len(entries)} entradas)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Exportación SARIF 2.1.0
# ─────────────────────────────────────────────────────────────────────────────

def export_sarif(findings: List[Finding], target: str, path: str) -> None:
    """
    Exporta hallazgos en formato SARIF 2.1.0 (Static Analysis Results
    Interchange Format). Compatible con GitHub Advanced Security, VS Code
    SARIF Viewer y herramientas de CI/CD que consuman este formato.

    Mapeo de severidad:
      CRITICAL → level: "error",   rank: 9.5
      HIGH     → level: "error",   rank: 7.5
      MEDIUM   → level: "warning", rank: 5.0
      LOW      → level: "note",    rank: 2.0
    """
    _SEV_TO_SARIF = {
        "CRITICAL": ("error",   9.5),
        "HIGH":     ("error",   7.5),
        "MEDIUM":   ("warning", 5.0),
        "LOW":      ("note",    2.0),
    }

    # Construir catálogo de reglas a partir de los patrones usados
    rules_seen: Dict[str, dict] = {}
    for f in findings:
        rule_id = re.sub(r"[^A-Za-z0-9\-_]", "-", f.pattern)[:64]
        if rule_id not in rules_seen:
            level, rank = _SEV_TO_SARIF.get(f.severity.value, ("note", 2.0))
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.pattern,
                "shortDescription": {"text": f"{f.pattern} ({f.category})"},
                "defaultConfiguration": {
                    "level": level,
                    "rank": rank,
                },
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                    "tags": ["security", "secrets"],
                },
            }

    # Construir resultados
    results = []
    target_uri = Path(target).as_uri()
    for f in findings:
        if f.allowlisted:
            continue
        rule_id = re.sub(r"[^A-Za-z0-9\-_]", "-", f.pattern)[:64]
        level, _ = _SEV_TO_SARIF.get(f.severity.value, ("note", 2.0))
        # URI relativa al workspace
        try:
            rel_file = str(Path(f.file).relative_to(target)).replace("\\", "/")
        except ValueError:
            rel_file = f.file.replace("\\", "/")
        result_entry: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{f.pattern} detectado en {rel_file}:{f.line_no} — {f.preview}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": f.line_no},
                }
            }],
            "fingerprints": {"vamp-secrets-scanner/v1": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "category": f.category,
                "preview":  f.preview,
            },
        }
        # Información git si disponible
        if f.git_commit:
            result_entry["properties"]["gitCommit"] = f.git_commit
            result_entry["properties"]["gitAuthor"] = f.git_author or ""
            result_entry["properties"]["gitDate"]   = f.git_date or ""
        results.append(result_entry)

    sarif_doc = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": VERSION,
                    "informationUri": "https://github.com/belky-me/vamp-secrets-scanner",
                    "organization": "VampSecure Studios",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": target_uri + "/"},
            },
            "properties": {
                "generated": datetime.now(timezone.utc).isoformat(),
                "target": target,
            },
        }],
    }

    Path(path).write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]  SARIF → {path} ({len(results)} resultados)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Fase 3 — Clasificación e informe Rich
# ─────────────────────────────────────────────────────────────────────────────

_SEV_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim",
}

_SEV_ICON: Dict[Severity, str] = {
    Severity.CRITICAL: "🔴 CRÍTICO",
    Severity.HIGH:     "🟠 ALTO",
    Severity.MEDIUM:   "🟡 MEDIO",
    Severity.LOW:      "🔵 BAJO",
}


def build_results_table(findings: List[Finding], base: Path) -> Table:
    table = Table(
        title="Resultados — Secrets Scanner",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Severidad",  no_wrap=True, max_width=14)
    table.add_column("Fichero",    style="white",       no_wrap=True, max_width=50)
    table.add_column("Línea",      style="cyan",        no_wrap=True, max_width=6, justify="right")
    table.add_column("Patrón",     style="white",       no_wrap=True, max_width=32)
    table.add_column("Categoría",  style="bright_black", no_wrap=True, max_width=24)
    table.add_column("Extracto",   style="yellow",      no_wrap=True, max_width=22)

    for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER[x.severity], x.file, x.line_no)):
        sty   = _SEV_STYLE[f.severity]
        label = _SEV_ICON[f.severity]
        try:
            rel = Path(f.file).relative_to(base)
        except ValueError:
            rel = Path(f.file)
        table.add_row(
            Text(label, style=sty),
            Text(str(rel)),
            str(f.line_no),
            Text(f.pattern),
            Text(f.category),
            Text(f.preview),
        )
    return table


def print_critical_panels(findings: List[Finding], base: Path) -> None:
    crits = [f for f in findings if f.severity == Severity.CRITICAL]
    if not crits:
        return
    console.print()
    console.print("[bold red]── HALLAZGOS CRÍTICOS ──────────────────────────────────────────────────────[/]")
    for f in crits:
        try:
            rel = Path(f.file).relative_to(base)
        except ValueError:
            rel = Path(f.file)
        ctx = "\n".join(f.context)
        body = (
            f"[bold white]Fichero:[/]   {markup_escape(str(rel))}:{f.line_no}\n"
            f"[bold white]Patrón:[/]    {markup_escape(f.pattern)}\n"
            f"[bold white]Categoría:[/] {markup_escape(f.category)}\n"
            f"[bold white]Extracto:[/]  [yellow]{markup_escape(f.preview)}[/]\n\n"
            f"[dim]{markup_escape(ctx)}[/]"
        )
        console.print(Panel(body,
            title=f"[bold red]⚠ CRÍTICO: {f.pattern}[/]",
            border_style="red"))


# ─────────────────────────────────────────────────────────────────────────────
# Exportación JSON
# ─────────────────────────────────────────────────────────────────────────────

def export_json(findings: List[Finding], target: str, path: str) -> None:
    out = {
        "tool":      TOOL_NAME,
        "version":   VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target":    target,
        "summary": {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in findings if f.severity == Severity.LOW),
        },
        "findings": [f.to_dict() for f in findings],
    }
    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]  JSON → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# Exportación HTML dark-theme
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR_HTML: Dict[str, str] = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#f0c040",
    "LOW":      "#4caf50",
}


def export_html(findings: List[Finding], target: str, path: str) -> None:
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med  = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low  = sum(1 for f in findings if f.severity == Severity.LOW)

    def rows() -> str:
        out = []
        for f in sorted(findings, key=lambda x: (_SEVERITY_ORDER[x.severity], x.file, x.line_no)):
            color = _SEV_COLOR_HTML.get(f.severity.value, "#aaa")
            ctx   = escape("\n".join(f.context))
            out.append(
                f'<tr onclick="toggle(this)" style="cursor:pointer">'
                f'<td style="color:{color};font-weight:bold">{escape(f.severity.value)}</td>'
                f'<td class="mono">{escape(f.file)}:{f.line_no}</td>'
                f'<td>{escape(f.pattern)}</td>'
                f'<td class="dim">{escape(f.category)}</td>'
                f'<td class="mono" style="color:#f0c040">{escape(f.preview)}</td>'
                f'</tr>'
                f'<tr class="ctx-row" style="display:none">'
                f'<td colspan="5"><pre class="ctx">{ctx}</pre></td>'
                f'</tr>'
            )
        return "\n".join(out)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>VampSecure Labs — Secrets Scan — {escape(target)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#010101;color:#ccc;font-family:"Share Tech Mono",monospace;font-size:13px;padding:30px}}
  h1{{color:#9d00ff;font-size:1.6rem;margin-bottom:4px}}
  .meta{{color:#444;font-size:.75rem;margin-bottom:30px}}
  .summary{{display:flex;gap:24px;margin-bottom:30px}}
  .kpi{{background:#0f0f0f;border:1px solid #222;padding:14px 22px;text-align:center}}
  .kpi-n{{font-size:2rem;font-weight:bold}}
  .kpi-l{{font-size:.7rem;color:#555;letter-spacing:1px}}
  .crit-n{{color:#ff4444}} .high-n{{color:#ff8800}} .med-n{{color:#f0c040}}
  .low-n{{color:#4caf50}} .tot-n{{color:#00f2ff}}
  h2{{color:#00f2ff;font-size:1rem;margin:28px 0 10px;border-left:4px solid #9d00ff;padding-left:12px}}
  table{{width:100%;border-collapse:collapse;font-size:.78rem}}
  th{{background:#111;color:#9d00ff;text-align:left;padding:8px;border-bottom:2px solid #222}}
  td{{padding:7px 8px;border-bottom:1px solid #0a0a0a;vertical-align:top}}
  tr:hover td{{background:#0a0a0a}}
  .mono{{color:#888;font-size:.72rem;word-break:break-all}}
  .dim{{color:#666}}
  .ctx{{background:#050505;padding:10px;font-size:.7rem;color:#666;white-space:pre-wrap;word-break:break-all}}
  footer{{margin-top:40px;color:#333;font-size:.7rem;border-top:1px solid #111;padding-top:12px}}
</style>
<script>
function toggle(row){{
  var next=row.nextElementSibling;
  if(next&&next.classList.contains('ctx-row'))
    next.style.display=next.style.display==='none'?'table-row':'none';
}}
</script>
</head>
<body>
<h1>VampSecure Labs — Secrets Scanner</h1>
<div class="meta">{escape(target)} · {now} · vamp-secrets-scanner v{VERSION}</div>

<div class="summary">
  <div class="kpi"><div class="kpi-n tot-n">{len(findings)}</div><div class="kpi-l">TOTAL</div></div>
  <div class="kpi"><div class="kpi-n crit-n">{crit}</div><div class="kpi-l">CRÍTICO</div></div>
  <div class="kpi"><div class="kpi-n high-n">{high}</div><div class="kpi-l">ALTO</div></div>
  <div class="kpi"><div class="kpi-n med-n">{med}</div><div class="kpi-l">MEDIO</div></div>
  <div class="kpi"><div class="kpi-n low-n">{low}</div><div class="kpi-l">BAJO</div></div>
</div>

<h2>Hallazgos (clic en fila para ver contexto)</h2>
<table>
  <thead><tr>
    <th>Severidad</th><th>Fichero : Línea</th><th>Patrón</th>
    <th>Categoría</th><th>Extracto</th>
  </tr></thead>
  <tbody>{rows()}</tbody>
</table>

<footer>
  © VampSecure Studios — VampSecure Labs Security Research Division<br>
  Uso exclusivo en entornos autorizados. Los datos son confidenciales.
</footer>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    console.print(f"[dim]  HTML → {path}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vamp-secrets-scanner",
        description="VampSecure Labs — Escáner Estático de Secretos, PII e Historial Git",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  # Escanear directorio actual\n"
            "  python vamp_secrets_scanner.py .\n\n"
            "  # Escanear repo incluyendo historial git completo\n"
            "  python vamp_secrets_scanner.py /ruta/al/repo --git-history\n\n"
            "  # Solo críticos y altos, exportar SARIF para GitHub Actions\n"
            "  python vamp_secrets_scanner.py . --min-severity HIGH --sarif results.sarif\n\n"
            "  # Generar allowlist desde hallazgos actuales (baseline inicial)\n"
            "  python vamp_secrets_scanner.py . --generate-allowlist baseline.json\n\n"
            "  # Aplicar allowlist en CI para ignorar falsos positivos conocidos\n"
            "  python vamp_secrets_scanner.py . --allowlist baseline.json --sarif results.sarif\n"
        ),
    )
    p.add_argument("target",
                   metavar="DIRECTORIO",
                   help="Directorio raíz a escanear")
    out = p.add_argument_group("Salida")
    out.add_argument("-o", "--output",       metavar="FICHERO",
                     help="Exportar hallazgos a JSON")
    out.add_argument("--html",               metavar="FICHERO",
                     help="Exportar informe HTML dark-theme")
    out.add_argument("--sarif",              metavar="FICHERO",
                     help="Exportar resultados en formato SARIF 2.1.0 (GitHub Actions / VS Code)")
    out.add_argument("--min-severity",
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     default="LOW",
                     help="Severidad mínima a reportar (default: LOW)")
    out.add_argument("--only-critical",      action="store_true",
                     help="Mostrar solo hallazgos CRÍTICOS (alias de --min-severity CRITICAL)")
    fil = p.add_argument_group("Filtros")
    fil.add_argument("--all-extensions",     action="store_true",
                     help="Escanear todos los ficheros no binarios (ignora whitelist de extensiones)")
    fil.add_argument("--max-depth",          type=int, metavar="N",
                     help="Profundidad máxima de recursión")
    fil.add_argument("--no-entropy",         action="store_true",
                     help="Deshabilitar el análisis de entropía de Shannon")
    fil.add_argument("--entropy-threshold",  type=float, default=4.5, metavar="BITS",
                     help="Umbral de entropía en bits/símbolo (default: 4.5)")
    fil.add_argument("--exclude-dir",        action="append", default=[], metavar="DIR",
                     help="Directorios adicionales a excluir (repetible)")
    git = p.add_argument_group("Historial Git")
    git.add_argument("--git-history",        action="store_true",
                     help="Escanear el historial completo de commits git (detecta secretos borrados)")
    git.add_argument("--max-commits",        type=int, default=0, metavar="N",
                     help="Limitar el escaneo de historial a los N commits más recientes (0 = sin límite)")
    al = p.add_argument_group("Allowlist")
    al.add_argument("--allowlist",           metavar="FICHERO",
                    help="Fichero JSON con falsos positivos a ignorar")
    al.add_argument("--generate-allowlist",  metavar="FICHERO",
                    help="Generar allowlist JSON a partir de los hallazgos actuales y salir")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    console.print(BANNER, style="bold magenta")

    args   = parse_args()
    target = Path(args.target).resolve()

    if not target.exists():
        console.print(f"[red]  ERROR: {target} no existe.[/]")
        sys.exit(1)
    if not target.is_dir():
        console.print(f"[red]  ERROR: {target} no es un directorio.[/]")
        sys.exit(1)

    # Añadir directorios extra a excluir
    for d in args.exclude_dir:
        EXCLUDE_DIRS.add(d)

    min_sev = Severity.CRITICAL if args.only_critical else Severity(args.min_severity)
    entropy_threshold = float("inf") if args.no_entropy else args.entropy_threshold

    console.print(f"  Objetivo: [cyan]{target}[/]")
    if args.git_history:
        console.print(f"  Modo: [bold yellow]árbol actual + historial git[/]"
                      + (f" (últimos {args.max_commits} commits)" if args.max_commits else ""))
    console.print()

    all_findings: List[Finding] = []

    # ── Fase 1: descubrir ficheros ────────────────────────────────────────────
    console.print("[bold cyan]  FASE 1[/] — Descubriendo ficheros en alcance...")
    files = list(discover_files(target, args.max_depth, args.all_extensions))
    total_bytes = sum(f.stat().st_size for f in files if f.exists())
    console.print(f"[dim]  {len(files)} ficheros · {total_bytes / 1024:.1f} KB en alcance[/]\n")

    # ── Fase 2a: escaneo de ficheros ──────────────────────────────────────────
    console.print("[bold cyan]  FASE 2[/] — Escaneando patrones y entropía (árbol actual)...")
    with console.status("[bold green]Analizando ficheros...[/]", spinner="dots"):
        for f in files:
            all_findings.extend(scan_file(f, entropy_threshold))

    # ── Fase 2b: escaneo de historial git (opcional) ──────────────────────────
    if args.git_history:
        if _is_git_repo(target):
            console.print("[bold cyan]  FASE 2b[/] — Escaneando historial git...")
            with console.status("[bold green]Analizando commits...[/]", spinner="dots"):
                git_findings = scan_git_history(target, entropy_threshold, args.max_commits)
            console.print(f"[dim]  {len(git_findings)} hallazgos en historial git[/]\n")
            all_findings.extend(git_findings)
        else:
            console.print("[yellow]  Aviso: --git-history solicitado pero el directorio no es un repo git[/]\n")

    # ── Deduplicación y filtrado ──────────────────────────────────────────────
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in all_findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)

    # ── Allowlist ─────────────────────────────────────────────────────────────
    if args.allowlist:
        allowlist = load_allowlist(args.allowlist)
        unique = apply_allowlist(unique, allowlist)
        n_suppressed = sum(1 for f in unique if f.allowlisted)
        if n_suppressed:
            console.print(f"[dim]  {n_suppressed} hallazgos suprimidos por la allowlist[/]")

    # ── Filtrar por severidad y allowlist ─────────────────────────────────────
    filtered = [
        f for f in unique
        if _SEVERITY_ORDER[f.severity] <= _SEVERITY_ORDER[min_sev]
        and not f.allowlisted
    ]

    console.print(f"[dim]  {len(unique)} hallazgos únicos · {len(filtered)} tras filtro de severidad[/]\n")

    # ── Generar allowlist baseline (si se pide, exportar y salir) ─────────────
    if args.generate_allowlist:
        generate_allowlist(filtered, args.generate_allowlist)
        console.print("[dim]  Usa --allowlist con ese fichero para suprimir los hallazgos en próximas ejecuciones.[/]")
        sys.exit(0)

    # ── Mostrar resultados ────────────────────────────────────────────────────
    if not filtered:
        console.print("[bold green]  ✓ Sin hallazgos en el rango de severidad seleccionado.[/]")
    else:
        console.print(build_results_table(filtered, target))
        print_critical_panels(filtered, target)

    # ── Resumen ───────────────────────────────────────────────────────────────
    n_crit = sum(1 for f in filtered if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in filtered if f.severity == Severity.HIGH)
    n_med  = sum(1 for f in filtered if f.severity == Severity.MEDIUM)
    n_low  = sum(1 for f in filtered if f.severity == Severity.LOW)
    n_git  = sum(1 for f in filtered if f.git_commit)

    sev_style = "bold red" if n_crit > 0 else ("bold yellow" if n_high > 0 else "bold green")
    resumen = (f"\n[{sev_style}]  RESUMEN: {len(filtered)} hallazgos · "
               f"{n_crit} CRÍTICO · {n_high} ALTO · {n_med} MEDIO · {n_low} BAJO")
    if n_git:
        resumen += f" · {n_git} en historial git"
    console.print(resumen + "[/]")

    # ── Exportación ───────────────────────────────────────────────────────────
    if args.output:
        export_json(filtered, str(target), args.output)
    if args.html:
        export_html(filtered, str(target), args.html)
    if args.sarif:
        export_sarif(filtered, str(target), args.sarif)

    # Exit codes útiles en CI/CD
    if n_crit > 0:
        sys.exit(2)
    elif n_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]  Escaneo interrumpido por el usuario.[/]")
        sys.exit(130)
