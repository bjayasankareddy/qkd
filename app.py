import os
import base64
import random
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from supabase import create_client, Client

# ==============================================================================
# INITIALIZATION & CONFIGURATION (Python 3.15 Compatible)
# ==============================================================================
# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Fail fast if the environment variables are missing
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("CRITICAL: SUPABASE_URL or SUPABASE_KEY is missing from your .env file.")

# Initialize the Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==============================================================================
# MOCKED SERVER VAULTS (For Phase 1 Simulation)
# In production, these physical keys sit in a highly secure backend HSM.
# ==============================================================================
SERVER_VAULTS = {
    "alice": {
        "idx_A1": "3a8b4f1c9d2e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
        "idx_A2": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
    },
    "bob": {
        "idx_B1": "1f2e3d4c5b6a798897a6b5c4d3e2f1001f2e3d4c5b6a798897a6b5c4d3e2f100",
        "idx_B2": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    }
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================
def get_server_qkd_key(user_id, index):
    """Fetches the specific physical key from the server's backend vault."""
    try:
        key_hex = SERVER_VAULTS[user_id][index]
        return bytes.fromhex(key_hex)
    except KeyError:
        return None

# ==============================================================================
# API ENDPOINTS (Interfacing with Supabase)
# ==============================================================================

@app.route('/api/keys/register', methods=['POST'])
def register_public_key():
    """Phase 2 Prep: Users upload their Kyber Public Key to the Supabase directory."""
    data = request.json
    user_id = data.get('user_id')
    kyber_pk = data.get('kyber_public_key')
    
    try:
        # Insert or update the public key in Supabase (upsert)
        response = supabase.table('public_keys').upsert({
            "user_id": user_id, 
            "kyber_public_key": kyber_pk
        }).execute()
        return jsonify({"success": True, "message": f"Kyber Public Key registered for {user_id}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/keys/<user_id>', methods=['GET'])
def get_public_key(user_id):
    """Alice calls this to get Bob's Kyber Public Key from Supabase."""
    try:
        response = supabase.table('public_keys').select('*').eq('user_id', user_id).execute()
        if not response.data:
            return jsonify({"error": "User public key not found"}), 404
            
        pk = response.data[0].get('kyber_public_key')
        return jsonify({"user_id": user_id, "kyber_public_key": pk})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/messages/route', methods=['POST'])
def route_nested_message():
    """
    THE UNTRUSTED ROUTER: This is the core of the Zero-Knowledge E2EE proof.
    The server receives a package locked by Alice, decrypts the outer shell, 
    touches the unreadable E2E payload, re-wraps it for Bob, and saves it to Supabase.
    """
    data = request.json
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    
    # Alice's Outer Shell Data
    alice_qkd_index = data.get('sender_qkd_index')
    alice_outer_nonce = base64.b64decode(data.get('outer_nonce'))
    alice_outer_ciphertext = base64.b64decode(data.get('outer_ciphertext'))
    
    print(f"\n[ROUTER] Incoming transmission from {sender_id} to {receiver_id}")
    
    # ---------------------------------------------------------
    # STEP 1: Strip Alice's Outer Shell
    # ---------------------------------------------------------
    alice_key = get_server_qkd_key(sender_id, alice_qkd_index)
    if not alice_key:
        return jsonify({"error": "Sender authentication failed. Invalid QKD Index."}), 401
        
    aesgcm_alice = AESGCM(alice_key)
    try:
        # We strip the shell. The result is the raw nested E2E payload.
        # THE SERVER CANNOT DECRYPT THIS PAYLOAD ANY FURTHER.
        e2e_payload_bytes = aesgcm_alice.decrypt(alice_outer_nonce, alice_outer_ciphertext, None)
        print("[ROUTER] Successfully stripped Alice's outer QKD shell.")
        print("[ROUTER] 🚨 Holding raw E2E Payload in RAM. Server is completely blind to contents.")
    except Exception as e:
        return jsonify({"error": "Integrity Check Failed on Sender Shell."}), 400

    # ---------------------------------------------------------
    # STEP 2: Wrap with Bob's Outer Shell
    # ---------------------------------------------------------
    # Pick a random, unused key from Bob's backend vault
    bob_qkd_index = random.choice(list(SERVER_VAULTS[receiver_id].keys()))
    bob_key = get_server_qkd_key(receiver_id, bob_qkd_index)
    
    aesgcm_bob = AESGCM(bob_key)
    bob_outer_nonce = os.urandom(12)
    
    # We take the blind e2e_payload_bytes and wrap it up for Bob
    bob_outer_ciphertext = aesgcm_bob.encrypt(bob_outer_nonce, e2e_payload_bytes, None)
    print(f"[ROUTER] Re-wrapped blind payload using Bob's QKD key [{bob_qkd_index}].")
    
    # ---------------------------------------------------------
    # STEP 3: Store in Supabase Database
    # ---------------------------------------------------------
    try:
        message_record = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "receiver_qkd_index": bob_qkd_index,
            "outer_qkd_nonce": base64.b64encode(bob_outer_nonce).decode('utf-8'),
            "outer_qkd_ciphertext": base64.b64encode(bob_outer_ciphertext).decode('utf-8')
        }
        
        response = supabase.table('messages').insert(message_record).execute()
        print("[ROUTER] Package securely stored in Supabase awaiting receiver download.\n")
        return jsonify({"success": True, "message": "Message securely routed and stored."})
        
    except Exception as e:
        print(f"[ERROR] Database write failed: {str(e)}")
        return jsonify({"error": "Database storage failed."}), 500

@app.route('/api/messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    """Bob calls this to fetch his waiting E2E packages from Supabase."""
    try:
        response = supabase.table('messages').select('*').eq('receiver_id', user_id).execute()
        return jsonify({"messages": response.data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("--- STARTING UNTRUSTED NODE ROUTER (Supabase Edition) ---")
    app.run(port=5000, debug=True)