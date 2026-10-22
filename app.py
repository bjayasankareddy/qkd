import os
import base64
import random
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

app = Flask(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("CRITICAL: SUPABASE_URL or SUPABASE_KEY is missing from your .env file.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==============================================================================
# UTILITY: FETCH SERVER VAULT DYNAMICALLY FROM CLOUD DB
# ==============================================================================
def get_server_qkd_key(user_id, index):
    """Fetches the specific physical key dynamically from the Supabase private vault."""
    try:
        response = supabase.table('server_vaults').select('qkd_keys').eq('user_id', user_id).execute()
        if not response.data:
            return None
            
        vault_keys = response.data[0]['qkd_keys']
        key_hex = vault_keys.get(index)
        
        if key_hex:
            return bytes.fromhex(key_hex)
        return None
    except Exception as e:
        print(f"Database error fetching key: {e}")
        return None

def get_random_receiver_index(user_id):
    """Picks a random unused key index from the receiver's vault."""
    try:
        response = supabase.table('server_vaults').select('qkd_keys').eq('user_id', user_id).execute()
        if not response.data:
            return None
        
        vault_keys = response.data[0]['qkd_keys']
        # Extract all keys that start with 'idx_'
        valid_indexes = [k for k in vault_keys.keys() if k.startswith('idx_')]
        if valid_indexes:
            return random.choice(valid_indexes)
        return None
    except Exception:
        return None

# ==============================================================================
# API ENDPOINTS
# ==============================================================================

@app.route('/api/messages/route', methods=['POST'])
def route_nested_message():
    """
    THE UNTRUSTED ROUTER: Strips Alice's shell, rewraps for Bob, stores in DB.
    """
    data = request.json
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    
    alice_qkd_index = data.get('sender_qkd_index')
    alice_outer_nonce = base64.b64decode(data.get('outer_nonce'))
    alice_outer_ciphertext = base64.b64decode(data.get('outer_ciphertext'))
    
    # 1. Fetch Alice's key dynamically from the database vault
    alice_key = get_server_qkd_key(sender_id, alice_qkd_index)
    if not alice_key:
        return jsonify({"error": "Sender authentication failed. Invalid QKD Index."}), 401
        
    aesgcm_alice = AESGCM(alice_key)
    try:
        e2e_payload_bytes = aesgcm_alice.decrypt(alice_outer_nonce, alice_outer_ciphertext, None)
    except Exception as e:
        return jsonify({"error": "Integrity Check Failed on Sender Shell."}), 400

    # 2. Fetch Bob's key dynamically from the database vault
    bob_qkd_index = get_random_receiver_index(receiver_id)
    if not bob_qkd_index:
        return jsonify({"error": "Receiver vault not found."}), 404
        
    bob_key = get_server_qkd_key(receiver_id, bob_qkd_index)
    
    aesgcm_bob = AESGCM(bob_key)
    bob_outer_nonce = os.urandom(12)
    bob_outer_ciphertext = aesgcm_bob.encrypt(bob_outer_nonce, e2e_payload_bytes, None)
    
    # 3. Store in Supabase
    try:
        message_record = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "receiver_qkd_index": bob_qkd_index,
            "outer_qkd_nonce": base64.b64encode(bob_outer_nonce).decode('utf-8'),
            "outer_qkd_ciphertext": base64.b64encode(bob_outer_ciphertext).decode('utf-8')
        }
        
        supabase.table('messages').insert(message_record).execute()
        return jsonify({"success": True, "message": "Message securely routed."})
        
    except Exception as e:
        return jsonify({"error": "Database storage failed."}), 500

@app.route('/api/messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    try:
        response = supabase.table('messages').select('*').eq('receiver_id', user_id).execute()
        return jsonify({"messages": response.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/<user_id>', methods=['GET'])
def get_public_key(user_id):
    try:
        response = supabase.table('public_keys').select('*').eq('user_id', user_id).execute()
        if not response.data:
            return jsonify({"error": "User public key not found"}), 404
        return jsonify({"user_id": user_id, "kyber_public_key": response.data[0].get('kyber_public_key')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Vercel requires the variable to be named 'app'
if __name__ == '__main__':
    app.run(port=5000, debug=True)
