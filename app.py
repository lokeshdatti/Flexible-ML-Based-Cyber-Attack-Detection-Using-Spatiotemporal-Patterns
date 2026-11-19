from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from tensorflow.keras.models import load_model
import os
from werkzeug.utils import secure_filename
import json
import time
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load attack name mapping
ATTACK_MAPPING = {}
try:
    with open('attack_mapping.json', 'r') as f:
        ATTACK_MAPPING = json.load(f)
    print("✓ Attack mapping loaded successfully")
    print(f"  Mappings: {ATTACK_MAPPING}")
except FileNotFoundError:
    print("⚠️  Warning: attack_mapping.json not found - using numeric labels as fallback")
except Exception as e:
    print(f"⚠️  Warning: Could not load attack_mapping.json: {e}")

# Load models globally
print("Loading models...")
try:
    rf_model = joblib.load('rf_feature_extractor.pkl')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    lstm_model = load_model('rf_lstm_hybrid_model.h5')
    print("✓ All models loaded successfully")
    print(f"  Label encoder classes: {label_encoder.classes_}")
except Exception as e:
    print(f"Error loading models: {e}")
    rf_model = None
    scaler = None
    label_encoder = None
    lstm_model = None

# Attack type color mapping - updated for numeric label mapping
ATTACK_COLORS = {
    # Main mappings from attack_mapping.json
    'BENIGN': '#10b981',
    'Bot': '#8b5cf6',
    'DDoS': '#dc2626',
    'DoS GoldenEye': '#dc2626',
    'DoS Hulk': '#ef4444',
    'DoS Slowhttptest': '#991b1b',
    'DoS slowloris': '#b91c1c',
    'FTP-Patator': '#f87171',
    'PortScan': '#f59e0b',
    'SSH-Patator': '#fca5a5',
    'Web Attack - Brute Force': '#f97316',
    'Web Attack - XSS': '#fb923c',
    
    # Case variations
    'benign': '#10b981',
    'Benign': '#10b981',
    'bot': '#8b5cf6',
    'BOT': '#8b5cf6',
    'ddos': '#dc2626',
    'DDOS': '#dc2626',
    'portscan': '#f59e0b',
    'Port Scan': '#f59e0b',
    'Portscan': '#f59e0b',
    
    # Generic DoS
    'DoS': '#ef4444',
    'DOS': '#ef4444',
    'dos': '#ef4444',
    
    # Web Attack variants
    'Web Attack': '#f97316',
    'WebAttack': '#f97316',
    'Web Attack � Brute Force': '#f97316',
    'Web Attack � XSS': '#fb923c',
    'Web Attack � Sql Injection': '#ea580c',
    
    # Other common attacks
    'Infiltration': '#ec4899',
    'infiltration': '#ec4899',
    'Heartbleed': '#be123c',
    'heartbleed': '#be123c',
    'Brute Force': '#ef4444',
    'BruteForce': '#ef4444',
    'brute force': '#ef4444',
}

def get_attack_color(attack_type):
    """Get color for attack type with fallback logic"""
    # Try exact match
    if attack_type in ATTACK_COLORS:
        return ATTACK_COLORS[attack_type]
    
    # Try case-insensitive match
    normalized = attack_type.lower()
    for key, color in ATTACK_COLORS.items():
        if key.lower() == normalized:
            return color
    
    # Try partial match
    for key, color in ATTACK_COLORS.items():
        if normalized in key.lower() or key.lower() in normalized:
            return color
    
    # Default to red for unknown attacks
    return '#ff0000'

def pcap_to_features(pcap_file):
    """Convert PCAP file to feature dataframe"""
    try:
        packets = rdpcap(pcap_file)
        features_list = []
        
        for i, packet in enumerate(packets[:1000]):  # Limit to first 1000 packets
            if IP in packet:
                feature_dict = {
                    'Flow Duration': 0,
                    'Total Fwd Packets': 1 if packet[IP].src else 0,
                    'Total Backward Packets': 1 if packet[IP].dst else 0,
                    'Total Length of Fwd Packets': len(packet) if packet[IP].src else 0,
                    'Total Length of Bwd Packets': len(packet) if packet[IP].dst else 0,
                    'Fwd Packet Length Max': len(packet),
                    'Fwd Packet Length Min': len(packet),
                    'Fwd Packet Length Mean': len(packet),
                    'Fwd Packet Length Std': 0,
                    'Bwd Packet Length Max': 0,
                    'Bwd Packet Length Min': 0,
                    'Bwd Packet Length Mean': 0,
                    'Bwd Packet Length Std': 0,
                    'Flow Bytes/s': 0,
                    'Flow Packets/s': 0,
                    'Flow IAT Mean': 0,
                    'Flow IAT Std': 0,
                    'Flow IAT Max': 0,
                    'Flow IAT Min': 0,
                    'Fwd IAT Total': 0,
                    'Fwd IAT Mean': 0,
                    'Fwd IAT Std': 0,
                    'Fwd IAT Max': 0,
                    'Fwd IAT Min': 0,
                    'Bwd IAT Total': 0,
                    'Bwd IAT Mean': 0,
                    'Bwd IAT Std': 0,
                    'Bwd IAT Max': 0,
                    'Bwd IAT Min': 0,
                    'Fwd PSH Flags': 1 if TCP in packet and packet[TCP].flags & 0x08 else 0,
                    'Bwd PSH Flags': 0,
                    'Fwd URG Flags': 1 if TCP in packet and packet[TCP].flags & 0x20 else 0,
                    'Bwd URG Flags': 0,
                    'Fwd Header Length': packet[IP].ihl * 4 if IP in packet else 0,
                    'Bwd Header Length': 0,
                    'Fwd Packets/s': 0,
                    'Bwd Packets/s': 0,
                    'Min Packet Length': len(packet),
                    'Max Packet Length': len(packet),
                    'Packet Length Mean': len(packet),
                    'Packet Length Std': 0,
                    'Packet Length Variance': 0,
                    'FIN Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x01 else 0,
                    'SYN Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x02 else 0,
                    'RST Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x04 else 0,
                    'PSH Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x08 else 0,
                    'ACK Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x10 else 0,
                    'URG Flag Count': 1 if TCP in packet and packet[TCP].flags & 0x20 else 0,
                    'CWE Flag Count': 0,
                    'ECE Flag Count': 0,
                    'Down/Up Ratio': 0,
                    'Average Packet Size': len(packet),
                    'Avg Fwd Segment Size': len(packet),
                    'Avg Bwd Segment Size': 0,
                    'Fwd Header Length.1': packet[IP].ihl * 4 if IP in packet else 0,
                    'Fwd Avg Bytes/Bulk': 0,
                    'Fwd Avg Packets/Bulk': 0,
                    'Fwd Avg Bulk Rate': 0,
                    'Bwd Avg Bytes/Bulk': 0,
                    'Bwd Avg Packets/Bulk': 0,
                    'Bwd Avg Bulk Rate': 0,
                    'Subflow Fwd Packets': 1,
                    'Subflow Fwd Bytes': len(packet),
                    'Subflow Bwd Packets': 0,
                    'Subflow Bwd Bytes': 0,
                    'Init_Win_bytes_forward': packet[TCP].window if TCP in packet else 0,
                    'Init_Win_bytes_backward': 0,
                    'act_data_pkt_fwd': 1 if len(packet) > 0 else 0,
                    'min_seg_size_forward': len(packet),
                    'Active Mean': 0,
                    'Active Std': 0,
                    'Active Max': 0,
                    'Active Min': 0,
                    'Idle Mean': 0,
                    'Idle Std': 0,
                    'Idle Max': 0,
                    'Idle Min': 0, 
                    'Label': 0,  # Placeholder
                    'dow':5,  # Day of week (placeholder)
                }
                features_list.append(feature_dict)
        
        df = pd.DataFrame(features_list)
        return df
    
    except Exception as e:
        print(f"Error processing PCAP: {e}")
        return None

def predict_single_row(row_data):
    """Predict attack type for a single row"""
    try:
        # Ensure it's 2D
        if len(row_data.shape) == 1:
            row_data = row_data.reshape(1, -1)
        
        # Scale
        row_scaled = scaler.transform(row_data)
        
        # Get RF probabilities
        rf_probs = rf_model.predict_proba(row_scaled)
        
        # Combine features
        combined = np.concatenate([row_scaled, rf_probs], axis=1)
        
        # Reshape for LSTM
        lstm_input = combined.reshape(combined.shape[0], 1, combined.shape[1])
        
        # Predict
        prediction = lstm_model.predict(lstm_input, verbose=0)
        predicted_class = np.argmax(prediction, axis=1)[0]
        confidence = float(np.max(prediction))
        
        # Decode label with mapping support
        try:
            decoded_label = label_encoder.inverse_transform([predicted_class])[0]
            
            # Check if it's a number (means label encoder has numeric classes)
            if isinstance(decoded_label, (int, np.integer)):
                # Use mapping to get attack name
                attack_type = ATTACK_MAPPING.get(str(decoded_label), f"Attack_Type_{decoded_label}")
                print(f"  → Mapped {decoded_label} to {attack_type}")
            elif isinstance(decoded_label, bytes):
                attack_type = decoded_label.decode('utf-8')
            else:
                attack_type = str(decoded_label)
                # If it's still a number string, try mapping
                if attack_type.isdigit():
                    attack_type = ATTACK_MAPPING.get(attack_type, f"Attack_Type_{attack_type}")
                    print(f"  → Mapped numeric string to {attack_type}")
        except Exception as decode_error:
            print(f"Label decoding error: {decode_error}")
            # Fallback to mapping
            attack_type = ATTACK_MAPPING.get(str(predicted_class), f"Attack_Type_{predicted_class}")
        
        # Clean up attack type name
        attack_type = attack_type.strip()
        
        print(f"Predicted: Class={predicted_class}, Label={attack_type}, Confidence={confidence:.2f}")
        
        return {
            'attack_type': attack_type,
            'predicted_class': int(predicted_class),
            'confidence': confidence,
            'color': get_attack_color(attack_type)
        }
    
    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return {
            'attack_type': 'Error',
            'predicted_class': -1,
            'confidence': 0.0,
            'color': '#666666'
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    """Handle CSV file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'Only CSV files allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Load CSV
        df = pd.read_csv(filepath)
        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Remove label column if exists
        if 'Label' in df.columns:
            df = df.drop('Label', axis=1)
        
        # Store in session (use file for larger datasets)
        session_id = str(int(time.time() * 1000))
        session_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}.csv')
        df.to_csv(session_file, index=False)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'total_rows': len(df),
            'columns': df.columns.tolist()[:10]  # First 10 columns
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    """Handle PCAP file upload and convert to CSV"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
            return jsonify({'error': 'Only PCAP files allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Convert PCAP to features
        df = pcap_to_features(filepath)
        
        if df is None:
            return jsonify({'error': 'Failed to process PCAP file'}), 500
        
        # Store in session
        session_id = str(int(time.time() * 1000))
        session_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}.csv')
        df.to_csv(session_file, index=False)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'total_rows': len(df),
            'columns': df.columns.tolist()[:10]
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict_row', methods=['POST'])
def predict_row():
    """Predict single row from session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        row_index = data.get('row_index', 0)
        
        # Load session data
        session_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}.csv')
        if not os.path.exists(session_file):
            return jsonify({'error': 'Session not found'}), 404
        
        df = pd.read_csv(session_file)
        
        if row_index >= len(df):
            return jsonify({'error': 'Row index out of range'}), 400
        
        # Get row data
        row_data = df.iloc[row_index].values
        
        # Predict
        result = predict_single_row(row_data)
        
        # Add row data (first 10 features for display)
        result['row_data'] = df.iloc[row_index].head(10).to_dict()
        result['row_index'] = row_index
        
        # Debug logging
        print(f"\n{'='*60}")
        print(f"PREDICTION RESPONSE for row {row_index}:")
        print(f"  attack_type: {result['attack_type']} (type: {type(result['attack_type']).__name__})")
        print(f"  predicted_class: {result.get('predicted_class', 'N/A')}")
        print(f"  confidence: {result['confidence']:.3f}")
        print(f"  color: {result['color']}")
        print(f"{'='*60}\n")
        
        return jsonify(result)
    
    except Exception as e:
        print(f"ERROR in predict_row: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/get_stats', methods=['POST'])
def get_stats():
    """Get overall statistics for the session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        session_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{session_id}.csv')
        if not os.path.exists(session_file):
            return jsonify({'error': 'Session not found'}), 404
        
        df = pd.read_csv(session_file)
        
        return jsonify({
            'total_rows': len(df),
            'total_features': len(df.columns)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)