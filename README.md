import threading
import json
import base64
import time
import logging
import os
from datetime import datetime
from flask import Flask, jsonify, request, render_template, send_from_directory, abort
from flask_cors import CORS
import re
import hashlib
import random
import smtplib
from email.message import EmailMessage

PUBLIC_SHARE_FOLDER = "cloud_public_share"
os.makedirs(PUBLIC_SHARE_FOLDER, exist_ok=True)

class CloudCore:
    def __init__(self):
        self.connected_vms = {}
        self.file_registry = {}
        self.lock = threading.Lock()
        
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def _verify_password(self, stored_hash, provided_password):
        return stored_hash == self._hash_password(provided_password)

    def add_vm(self, vm_name, email, password, storage_limit_mb):
        with self.lock:
            if vm_name in self.connected_vms:
                return {"status": "error", "message": "Ce nom de compte/VM est déjà utilisé."}
            
            storage_mb = storage_limit_mb if storage_limit_mb > 0 else 500
            password_hash = self._hash_password(password)
            
            self.connected_vms[vm_name] = {
                'name': vm_name,
                'email': email,
                'password_hash': password_hash,
                'storage_limit': storage_mb * 1024 * 1024,
                'storage_used': 0,
                'join_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'files': []
            }
            os.makedirs(f"vm_{vm_name}", exist_ok=True)
            return {"status": "success", "vm": self.connected_vms[vm_name]}

    def get_vm_details(self, vm_name, password=None):
        with self.lock:
            vm = self.connected_vms.get(vm_name)
            if vm and password:
                if self._verify_password(vm['password_hash'], password):
                    vm_safe = vm.copy()
                    vm_safe.pop('password_hash', None)
                    return vm_safe
                else:
                    return None 
            if vm:
                vm_safe = vm.copy()
                vm_safe.pop('password_hash', None)
                return vm_safe
            return None

    def upload_file(self, vm_name, file_name, content_b64, is_private_store, is_public_share):
        with self.lock:
            if vm_name not in self.connected_vms:
                return {"status": "error", "message": "VM non trouvée"}
            
            if not is_private_store and not is_public_share:
                return {"status": "error", "message": "Aucune option de stockage ou de partage sélectionnée."}

            try:
                content_bytes = base64.b64decode(content_b64)
            except:
                return {"status": "error", "message": "Contenu du fichier invalide (Base64)"}

            file_size = len(content_bytes)
            vm = self.connected_vms[vm_name]

            if is_private_store:
                if vm['storage_used'] + file_size > vm['storage_limit']:
                    return {"status": "error", "message": "Limite de stockage privée dépassée."}
                
                file_path_private = os.path.join(f"vm_{vm_name}", file_name)
                with open(file_path_private, "wb") as f:
                    f.write(content_bytes)
                if file_name not in vm['files']:
                    vm['storage_used'] += file_size
                    vm['files'].append(file_name)
            
            if is_public_share:
                file_path_public = os.path.join(PUBLIC_SHARE_FOLDER, file_name)
                with open(file_path_public, "wb") as f:
                    f.write(content_bytes)
                if file_name not in self.file_registry:
                    self.file_registry[file_name] = []
                if vm_name not in self.file_registry[file_name]:
                    self.file_registry[file_name].append(vm_name)

            return {"status": "success", "file_size": file_size, "private": is_private_store, "shared": is_public_share}

app = Flask(__name__, static_folder="frontend/static", template_folder="frontend")
CORS(app) 
cloud_core = CloudCore()

# ===== CONFIGURATION OTP =====
otp_store = {}
OTP_VALIDITY_SECONDS = 300  # 5 minutes
OTP_MAX_ATTEMPTS = 5

# Configuration SMTP
SMTP_EMAIL = "fotsingnoussi.stephane@ictuniversity.edu.cm"
SMTP_PASSWORD = "qvkdqqfitahemskk"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def generate_otp():
    """Génère un code OTP à 6 chiffres"""
    return random.randint(100000, 999999)

def send_otp_email(destination_email, otp, vm_name):
    """Envoie l'OTP par email"""
    try:
        msg = EmailMessage()
        msg["Subject"] = "🔐 Code de Vérification OTP - My Cloud"
        msg["From"] = SMTP_EMAIL
        msg["To"] = destination_email
        msg.set_content(f"""
Bonjour,

Votre code de vérification OTP pour le compte "{vm_name}" est :

    {otp}

Ce code est valable pendant {OTP_VALIDITY_SECONDS // 60} minutes.

⚠️ Si vous n'êtes pas à l'origine de cette demande, ignorez cet email et changez votre mot de passe immédiatement.

— My Cloud Sécurité
        """)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            smtp.send_message(msg)
        
        logging.info(f"✅ OTP envoyé avec succès à {destination_email} pour VM {vm_name}")
        return True
    except smtplib.SMTPAuthenticationError:
        logging.error("❌ Erreur d'authentification SMTP")
        return False
    except smtplib.SMTPException as e:
        logging.error(f"❌ Erreur SMTP: {e}")
        return False
    except Exception as e:
        logging.error(f"❌ Erreur lors de l'envoi OTP: {e}")
        return False

def create_otp_record(vm_name):
    """Crée ou met à jour un enregistrement OTP"""
    otp = generate_otp()
    expiration = time.time() + OTP_VALIDITY_SECONDS
    
    otp_store[vm_name] = {
        "otp": otp,
        "expires": expiration,
        "attempts": 0,
        "created_at": time.time()
    }
    
    return otp

def cleanup_expired_otps():
    """Nettoie les OTPs expirés"""
    current_time = time.time()
    expired_vms = [vm for vm, data in otp_store.items() if current_time > data["expires"]]
    for vm in expired_vms:
        otp_store.pop(vm, None)
        logging.info(f"🗑️ OTP expiré nettoyé pour VM: {vm}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/vm', methods=['POST'])
def create_new_vm():
    """Création d'une nouvelle VM"""
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    storage_mb = int(data.get('storage_mb', 500)) if str(data.get('storage_mb', '500')).isdigit() else 500
    
    if not name or len(name) < 3 or not email or not password:
        return jsonify({"status": "error", "message": "Tous les champs sont requis."}), 400

    if len(password) < 8:
        return jsonify({"status": "error", "message": "Le mot de passe doit contenir au moins 8 caractères."}), 400
    if not re.search(r"[A-Z]", password):
        return jsonify({"status": "error", "message": "Le mot de passe doit contenir au moins une majuscule."}), 400
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
        return jsonify({"status": "error", "message": "Le mot de passe doit contenir au moins un caractère spécial."}), 400
    if not re.search(r"\d", password):
        return jsonify({"status": "error", "message": "Le mot de passe doit contenir au moins un chiffre."}), 400

    result = cloud_core.add_vm(name, email, password, storage_mb)
    if result['status'] == 'success':
        return jsonify({"status": "success", "message": f"Compte VM '{name}' créé avec succès"}), 201
    else:
        return jsonify(result), 400

@app.route('/api/vm/login', methods=['POST'])
def login_vm():
    """Connexion VM + génération OTP"""
    data = request.json
    name = data.get('name')
    password = data.get('password')

    if not name or not password:
        return jsonify({"status": "error", "message": "Nom de VM et mot de passe requis."}), 400

    vm = cloud_core.get_vm_details(name, password)
    if not vm:
        return jsonify({"status": "error", "message": "Identifiants invalides."}), 401

    cleanup_expired_otps()
    otp = create_otp_record(name)
    
    email_sent = send_otp_email(vm["email"], otp, name)
    
    response_data = {
        "status": "otp_required",
        "message": "Code OTP généré et envoyé par email.",
        "validity_seconds": OTP_VALIDITY_SECONDS
    }
    
    if not email_sent:
        response_data["simulated_otp"] = str(otp)
        response_data["note"] = "⚠️ SMTP error - OTP affiché pour test"
        logging.warning(f"🧪 MODE TEST - OTP pour {name}: {otp}")

    return jsonify(response_data), 200

@app.route('/api/vm/<vm_name>/otp/request', methods=['POST'])
def request_otp(vm_name):
    """Renvoie un nouvel OTP"""
    vm = cloud_core.get_vm_details(vm_name)
    if not vm:
        return jsonify({"status": "error", "message": "VM non trouvée."}), 404

    cleanup_expired_otps()
    
    if vm_name in otp_store:
        time_since_creation = time.time() - otp_store[vm_name].get("created_at", 0)
        if time_since_creation < 30:
            return jsonify({
                "status": "error",
                "message": f"Veuillez attendre {int(30 - time_since_creation)} secondes avant de demander un nouveau code."
            }), 429

    otp = create_otp_record(vm_name)
    email_sent = send_otp_email(vm["email"], otp, vm_name)
    
    response_data = {
        "status": "otp_required",
        "message": "Nouveau code OTP envoyé par email.",
        "validity_seconds": OTP_VALIDITY_SECONDS
    }
    
    if not email_sent:
        response_data["simulated_otp"] = str(otp)
        response_data["note"] = "⚠️ SMTP error - OTP affiché pour test"
        logging.warning(f"🧪 MODE TEST - Nouvel OTP pour {vm_name}: {otp}")
    
    return jsonify(response_data), 200

@app.route('/api/vm/verify-otp', methods=['POST'])
def verify_otp():
    """Vérifie l'OTP"""
    data = request.json
    vm_name = data.get("vm_name")
    otp_input = data.get("otp")

    if not vm_name or not otp_input:
        return jsonify({"status": "error", "message": "OTP et VM requis."}), 400

    cleanup_expired_otps()
    
    record = otp_store.get(vm_name)
    if not record:
        return jsonify({"status": "error", "message": "Aucun OTP en attente. Veuillez demander un nouveau code."}), 400

    if time.time() > record["expires"]:
        otp_store.pop(vm_name, None)
        return jsonify({
            "status": "error",
            "message": f"Code OTP expiré. Validité: {OTP_VALIDITY_SECONDS // 60} minutes."
        }), 401

    if record["attempts"] >= OTP_MAX_ATTEMPTS:
        otp_store.pop(vm_name, None)
        return jsonify({
            "status": "error",
            "message": "Trop de tentatives échouées. Veuillez demander un nouveau code."
        }), 429

    record["attempts"] += 1

    if str(record["otp"]) != str(otp_input):
        remaining_attempts = OTP_MAX_ATTEMPTS - record["attempts"]
        return jsonify({
            "status": "error",
            "message": f"Code OTP incorrect. {remaining_attempts} tentative(s) restante(s)."
        }), 401

    otp_store.pop(vm_name, None)
    logging.info(f"✅ Authentification OTP réussie pour {vm_name}")

    return jsonify({
        "status": "success",
        "message": "Authentification OTP réussie. Bienvenue !",
        "vm_name": vm_name
    }), 200

@app.route('/api/vm/<vm_name>', methods=['GET'])
def get_single_vm(vm_name):
    """Récupère les détails d'une VM"""
    vm = cloud_core.get_vm_details(vm_name)
    if vm:
        return jsonify(vm), 200
    else:
        return jsonify({"status": "error", "message": f"Compte/VM '{vm_name}' non trouvé."}), 404

@app.route('/api/vm/<vm_name>/upload', methods=['POST'])
def upload_vm_file(vm_name):
    """Upload un fichier"""
    data = request.json
    file_name = data.get('file_name')
    content_b64 = data.get('content_b64')
    is_private_store = data.get('is_private_store', False)
    is_public_share = data.get('is_public_share', False)
    
    if not file_name or not content_b64:
        return jsonify({"status": "error", "message": "Nom de fichier et contenu requis"}), 400
        
    result = cloud_core.upload_file(vm_name, file_name, content_b64, is_private_store, is_public_share)
    if result['status'] == 'success':
        return jsonify(result), 200
    else:
        return jsonify(result), 400

@app.route('/api/vm/<vm_name>/files/<file_name>', methods=['GET'])
def download_vm_file(vm_name, file_name):
    """Télécharge un fichier privé"""
    try:
        vm_folder = f"vm_{vm_name}"
        return send_from_directory(vm_folder, file_name, as_attachment=True)
    except Exception as e:
        return jsonify({"status": "error", "message": "Fichier privé non trouvé."}), 404

@app.route('/api/file/request/<file_name>', methods=['GET'])
def request_file(file_name):
    """Vérifie si un fichier public existe"""
    file_path = os.path.join(PUBLIC_SHARE_FOLDER, file_name)
    if os.path.exists(file_path):
        return jsonify({"status": "success", "available": True, "download_url": f"/api/file/public/{file_name}"}), 200
    else:
        return jsonify({"status": "success", "available": False, "message": "Fichier non trouvé."}), 404

@app.route('/api/file/public/<file_name>', methods=['GET'])
def download_public_file(file_name):
    """Télécharge un fichier public"""
    try:
        return send_from_directory(PUBLIC_SHARE_FOLDER, file_name, as_attachment=True)
    except Exception as e:
        return jsonify({"status": "error", "message": "Fichier public non trouvé."}), 404

@app.before_request
def periodic_cleanup():
    """Nettoyage périodique des OTPs expirés"""
    if random.random() < 0.1:
        cleanup_expired_otps()

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    print("=" * 60)
    print("🚀 API My Cloud en cours d'exécution")
    print("=" * 60)
    print(f"📍 URL: http://127.0.0.1:5000")
    print(f"📧 Email SMTP: {SMTP_EMAIL}")
    print(f"✅ Statut SMTP: Configuré")
    print(f"⏱️  Validité OTP: {OTP_VALIDITY_SECONDS // 60} minutes")
    print(f"🔒 Tentatives max: {OTP_MAX_ATTEMPTS}")
    print("=" * 60)
    app.run(debug=True)
