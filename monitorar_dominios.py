#!/usr/bin/env python3
"""Monitor expiration dates for .br domains using Registro.br RDAP/WHOIS."""
import csv
import json
import os
import smtplib
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

DOMAINS = [
    "cassolcenterlar.com.br",
    "cassol.com.br",
    "debus.com.br",
    "avallonturismo.com.br",
    "agrograopalotina.com.br",
    "jltech.com.br",
]
RDAP_URL = "https://rdap.registro.br/domain/{}"
OUT = Path(__file__).resolve().parent
TIMEOUT = 20


def parse_date(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def rdap_lookup(domain):
    url = RDAP_URL.format(domain)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "JLCassol-DomainExpiryMonitor/1.0",
            "Accept": "application/rdap+json, application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))

    expiration = None
    for event in data.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action in {"expiration", "registrar expiration", "expiry"}:
            expiration = parse_date(event.get("eventDate"))
            if expiration:
                break

    return {
        "domain": domain,
        "status": ", ".join(data.get("status", [])) or "não informado",
        "expiration": expiration,
        "source": url,
        "result": "RDAP consultado" if expiration else "RDAP respondeu sem evento de expiração reconhecível",
        "error": "",
    }


def whois_lookup(domain):
    with socket.create_connection(("whois.registro.br", 43), timeout=TIMEOUT) as sock:
        sock.sendall((domain + "\r\n").encode("ascii"))
        sock.settimeout(TIMEOUT)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    body = b"".join(chunks).decode("latin-1", errors="replace")
    expiration = None
    for line in body.splitlines():
        low = line.strip().lower()
        if any(low.startswith(prefix) for prefix in (
            "expires:", "expiration:", "expira:", "data de expiração:", "data de expiracao:"
        )):
            raw = line.split(":", 1)[1].strip()
            expiration = parse_date(raw)
            if not expiration:
                for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y%m%d"):
                    try:
                        expiration = datetime.strptime(raw[:10], fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        pass
            if expiration:
                break
    return {
        "domain": domain,
        "status": "consultado via WHOIS; status não interpretado",
        "expiration": expiration,
        "source": "whois.registro.br:43",
        "result": "WHOIS consultado" if expiration else "WHOIS respondeu sem data reconhecível",
        "error": "",
    }


def check_domain(domain):
    rdap_error = ""
    try:
        result = rdap_lookup(domain)
        if result["expiration"]:
            return result
        try:
            fallback = whois_lookup(domain)
            if fallback["expiration"]:
                return fallback
            result["source"] += " + whois.registro.br"
            result["result"] += "; WHOIS sem data reconhecível"
            return result
        except Exception as exc:
            result["source"] += " + whois.registro.br (falhou)"
            result["result"] += "; fallback WHOIS falhou"
            result["error"] = str(exc)
            return result
    except Exception as exc:
        rdap_error = str(exc)
    try:
        result = whois_lookup(domain)
        if result["expiration"]:
            return result
        result["result"] = "RDAP falhou; WHOIS sem data reconhecível"
        result["error"] = rdap_error
        return result
    except Exception as exc:
        return {
            "domain": domain,
            "status": "não confirmado",
            "expiration": None,
            "source": "RDAP Registro.br + WHOIS Registro.br",
            "result": "consulta falhou",
            "error": f"RDAP: {rdap_error}; WHOIS: {exc}",
        }


def main():
    now = datetime.now(timezone.utc)
    checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
    rows = []
    attention = []

    for domain in DOMAINS:
        item = check_domain(domain)
        expiration = item["expiration"]
        if expiration:
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=timezone.utc)
            days = (expiration.date() - now.date()).days
            expiration_text = expiration.astimezone().strftime("%Y-%m-%d %H:%M %Z")
            if days < 0:
                alert = "VENCIDO — confirme o status com o registrador"
                attention.append(f"{domain}: vencimento informado no passado ({expiration_text}).")
            elif days <= 1:
                alert = "ALERTA: vence em até 1 dia"
                attention.append(f"{domain}: vence em {days} dia(s), data informada {expiration_text}.")
            elif days <= 7:
                alert = "ALERTA: vence em até 7 dias"
                attention.append(f"{domain}: vence em {days} dia(s), data informada {expiration_text}.")
            else:
                alert = "Sem alerta imediato"
            days_text = str(days)
        else:
            expiration_text = "NÃO CONFIRMADA"
            days_text = "indisponível"
            alert = "ATENÇÃO: expiração não confirmada"
            attention.append(f"{domain}: {item['result']}; erro: {item['error'] or 'não informado'}.")

        rows.append({
            "checked_at": checked_at,
            "domain": domain,
            "registration_status": item["status"],
            "expiration_date": expiration_text,
            "days_remaining": days_text,
            "alert": alert,
            "result": item["result"],
            "source": item["source"],
            "error": item["error"],
        })

    csv_path = OUT / "relatorio_dominios.csv"
    txt_path = OUT / "relatorio_dominios.txt"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    report = [
        "RELATÓRIO DE MONITORAMENTO DE DOMÍNIOS",
        f"Consulta realizada: {checked_at}",
        "",
    ]
    for row in rows:
        report.append(
            f"{row['domain']} | expiração: {row['expiration_date']} | dias restantes: {row['days_remaining']} "
            f"| alerta: {row['alert']} | resultado: {row['result']} | fonte: {row['source']}"
        )
        if row["error"]:
            report.append(f"  Erro: {row['error']}")
    report += ["", "ITENS QUE EXIGEM ATENÇÃO:"]
    report += attention or ["Nenhum domínio dentro da janela de 7 dias; datas consultadas confirmadas."]
    text = "\n".join(report)
    txt_path.write_text(text, encoding="utf-8")
    print(text)

    send_email_if_configured(text, csv_path)


def send_email_if_configured(report, csv_path):
    host = os.getenv("SMTP_HOST")
    recipient = os.getenv("ALERT_TO")
    sender = os.getenv("ALERT_FROM") or os.getenv("SMTP_USER")
    if not (host and recipient and sender):
        print("E-mail não enviado: configure SMTP_HOST, ALERT_TO e ALERT_FROM/SMTP_USER nos GitHub Secrets.")
        return

    message = EmailMessage()
    message["Subject"] = "Monitoramento de expiração de domínios"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(report)
    with csv_path.open("rb") as handle:
        message.add_attachment(handle.read(), maintype="text", subtype="csv", filename=csv_path.name)

    raw_port = os.getenv("SMTP_PORT", "587").strip()
    if not raw_port.isdigit():
        print(f"AVISO: SMTP_PORT inválido ({raw_port!r}); usando a porta padrão 587.")
        raw_port = "587"
    port = int(raw_port)
    username = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(message)
    print(f"E-mail enviado para {recipient}.")


if __name__ == "__main__":
    main()
