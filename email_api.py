from flask import Flask, request, jsonify
from flask_cors import CORS
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib, os, secrets, hashlib, datetime as dt
from dotenv import load_dotenv
from smtplib import SMTP_SSL
load_dotenv()
# topo do email_api.py
from passlib.hash import pbkdf2_sha256  # add isto

# ---- DB (SQLAlchemy Core) ----
from sqlalchemy import create_engine, text

# Hash de senha (bcrypt)
import bcrypt

app = Flask(__name__)
CORS(app)

# ---------------- Email (Locaweb) ----------------
SMTP_HOST = os.getenv("SMTP_HOST", "mail.faixabet.com.br")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "sac@faixabet.com.br")
SMTP_PASS = os.getenv("SMTP_PASS", "SENHA_AQUI")
SMTP_USE_SSL = (SMTP_PORT == 465)



# ---------------- DB ----------------
DATABASE_URL = os.getenv("DATABASE_URL")  # ex: postgres://user:pass@host/db
engine = create_engine(DATABASE_URL, pool_pre_ping=True)    
import socket

def send_mail_html(destino: str, assunto: str, html: str):
    global SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS   # <-- aqui está a correção

    msg = MIMEMultipart("alternative")
    msg["From"] = f"fAIxaBet <{SMTP_USER}>"
    msg["To"] = destino
    msg["Subject"] = assunto
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        # ✅ força IPv4 (Locaweb não aceita IPv6)
        ipv4 = socket.gethostbyname(SMTP_HOST)

        server = smtplib.SMTP(ipv4, SMTP_PORT, timeout=12)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()

        print("✅ Email enviado via IPv4 + Porta 587 + STARTTLS")

    except Exception as e:
        print("❌ Erro ao enviar email (IPv4 forçado):", e)


def hash_token(token: str) -> str:
    # Não guardar token em claro
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

# substitua a função hash_password por:
def hash_password(plain: str) -> str:
    return pbkdf2_sha256.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# ---------------- Rotas ----------------
@app.route("/")
def home():
    return "Backend fAIxaBet ativo ✅"

# (Sua rota existente) Envio de palpites
@app.route("/send_palpite", methods=["POST"])
def send_palpite():
    try:
        data = request.get_json()
        email = data.get("email")
        sorteio = ", ".join(map(str, data.get("sorteio", [])))
        ai = ", ".join(map(str, data.get("ai", [])))
        jogador = ", ".join(map(str, data.get("jogador", [])))

        if not email:
            return jsonify({"status": "error", "message": "E-mail inválido"}), 400

        corpo = f"""
        <h2>🎯 Seus palpites do simulador fAIxaBet</h2>
        <p><b>Sorteio:</b> {sorteio}</p>
        <p><b>AI:</b> {ai}</p>
        <p><b>Jogador:</b> {jogador}</p>
        """

        send_mail_html(email, "🎯 Seus palpites do simulador fAIxaBet", corpo)
        return jsonify({"status": "ok", "message": "E-mail enviado com sucesso!"})
    except Exception as e:
        print("❌ Erro ao enviar e-mail:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------- Esqueci minha senha: cria token e envia e-mail ----------
@app.route("/password/forgot", methods=["POST"])
def password_forgot():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()

    # IP real para rate limit
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0]

    try:
        with engine.begin() as conn:

            # --- RATE LIMIT POR IP (3 por 15 minutos) ---
            recent_requests = conn.execute(text("""
                SELECT COUNT(*) FROM password_reset_log
                WHERE ip = :ip AND created_at > NOW() - INTERVAL '15 minutes'
            """), {"ip": ip}).scalar()

            if recent_requests >= 3:
                return jsonify({"ok": True}), 200  # Resposta neutra (não revela nada)

            # Registrar tentativa
            conn.execute(text("""
                INSERT INTO password_reset_log (ip, email)
                VALUES (:ip, :email)
            """), {"ip": ip, "email": email})

            # Buscar usuário
            user = conn.execute(
                text("SELECT id FROM usuarios WHERE LOWER(email)=:e LIMIT 1"),
                {"e": email}
            ).mappings().first()

            # Mesmo comportamento caso e-mail não exista
            if not user:
                return jsonify({"ok": True}), 200

            # Se já existe token válido → não gerar outro
            active_token = conn.execute(text("""
                SELECT 1 FROM password_reset
                WHERE user_id = :uid
                AND used_at IS NULL
                AND expires_at > NOW()
            """), {"uid": user["id"]}).first()

            if active_token:
                return jsonify({"ok": True}), 200

            # Criar token novo
            token = secrets.token_urlsafe(32)
            token_h = hash_token(token)
            expires = dt.datetime.utcnow() + dt.timedelta(minutes=15)

            conn.execute(text("""
                INSERT INTO password_reset (user_id, token_hash, expires_at)
                VALUES (:uid, :thash, :exp)
            """), {"uid": user["id"], "thash": token_h, "exp": expires})

        # Criar link de reset
        base_front = os.getenv("FRONT_RESET_BASE", "https://faixabet.com.br/app/reset-password")
        reset_link = f"{base_front}?token={token}"

        # HTML bonito
        html = f"""
        <div style="font-family:'Segoe UI',Arial,sans-serif; max-width:480px; margin:auto; padding:20px; border-radius:12px; background:#ffffff; border:1px solid #e5e7eb;">
          <h2 style="color:#16a34a; text-align:center; font-weight:600;">Redefinição de senha</h2>
          <p style="font-size:15px; color:#374151;">
            Clique abaixo para redefinir sua senha (válido por 15 minutos):
          </p>
          <p style="text-align:center; margin:28px 0;">
            <a href="{reset_link}" style="background-color:#16a34a;color:white;padding:14px 22px;text-decoration:none;border-radius:8px;font-size:16px;display:inline-block;">
              Redefinir minha senha
            </a>
          </p>
        </div>
        """

        send_mail_html(email, "🔐 Redefinir senha — fAIxaBet", html)
        return jsonify({"ok": True}), 200

    except Exception as e:
        print("forgot error:", e)
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------- Aplicar nova senha ----------
@app.route("/password/reset", methods=["POST"])
def password_reset():
    try:
        data = request.get_json(force=True)
        token = data.get("token", "")
        new_password = data.get("new_password", "")

        if not token or not new_password or len(new_password) < 6:
            return jsonify({"ok": False, "error": "Dados inválidos"}), 400

        token_h = hash_token(token)

        with engine.begin() as conn:
            row = conn.execute(text("""
                SELECT id, user_id, expires_at, used_at
                FROM password_reset
                WHERE token_hash = :th
                ORDER BY created_at DESC
                LIMIT 1
            """), {"th": token_h}).mappings().first()

            if not row:
                return jsonify({"ok": False, "error": "Token inválido"}), 400

            if row["used_at"] is not None:
                return jsonify({"ok": False, "error": "Token já utilizado"}), 400

            if dt.datetime.utcnow() > row["expires_at"]:
                return jsonify({"ok": False, "error": "Token expirado"}), 400

            # Hash PBKDF2
            new_hash = hash_password(new_password)

            # ✅ Aqui estava o erro — agora CORRETO:
            conn.execute(text("""
                UPDATE usuarios SET senha = :h WHERE id = :uid
            """), {"h": new_hash, "uid": row["user_id"]})

            conn.execute(text("""
                UPDATE password_reset SET used_at = NOW() WHERE id = :id
            """), {"id": row["id"]})

        return jsonify({"ok": True}), 200

    except Exception as e:
        print("reset error:", e)
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------- Boot local ----------------
if __name__ == "__main__":
    print("🚀 Servidor Flask iniciado na porta 5000...")
    app.run(host="0.0.0.0", port=5000, debug=True)
