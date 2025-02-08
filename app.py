from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
import pickle
import ipaddress
from sklearn.preprocessing import StandardScaler
from src.HackTU.pipeline.Apt_Data_Extraction import NetworkFlowAnalyzer
from src.HackTU.pipeline.Phishing_Data_Extraction import URLFeatureExtractor
import subprocess
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Load APT detection models
APT_MODEL_PATH = "models/aptDetection/apt_detection_model.pkl"
APT_SCALER_PATH = "models/aptDetection/scaler.pkl"
APT_LABEL_ENCODER_PATH = "models/aptDetection/label_encoder.pkl"

# Load Phishing detection models
PHISHING_MODEL_PATH = "models/phishingDetection/phishing_model.pkl"
PHISHING_SCALER_PATH = "models/phishingDetection/phishing_scaler.pkl"
PHISHING_LABEL_ENCODER_PATH = "models/phishingDetection/phishing_label_encoder.pkl"

# Load all models and scalers
with open(APT_MODEL_PATH, "rb") as model_file:
    apt_model = pickle.load(model_file)

with open(APT_SCALER_PATH, "rb") as scaler_file:
    apt_scaler = pickle.load(scaler_file)

with open(APT_LABEL_ENCODER_PATH, "rb") as le_file:
    apt_label_encoder = pickle.load(le_file)

with open(PHISHING_MODEL_PATH, "rb") as model_file:
    phishing_model = pickle.load(model_file)

with open(PHISHING_SCALER_PATH, "rb") as scaler_file:
    phishing_scaler = pickle.load(scaler_file)

with open(PHISHING_LABEL_ENCODER_PATH, "rb") as le_file:
    phishing_label_encoder = pickle.load(le_file)

print("All Models and Scalers Loaded Successfully!")

# Function to convert IP addresses to numeric format
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0

# Define required features for APT detection
APT_SELECTED_FEATURES = [
    "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
    "Flow Duration", "Total Fwd Packets", "Total Bwd Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s"
]

# Define the expected feature order for phishing detection
PHISHING_FEATURES = [
    "qty_dot_url", "qty_hyphen_url", "qty_underline_url", "qty_slash_url",
    "qty_questionmark_url", "qty_equal_url", "qty_at_url", "qty_and_url",
    "qty_exclamation_url", "qty_space_url", "domain_length", "qty_dot_domain",
    "qty_hyphen_domain", "qty_underline_domain", "qty_vowels_domain",
    "domain_in_ip", "directory_length", "qty_dot_directory",
    "qty_hyphen_directory", "qty_underline_directory", "qty_slash_directory",
    "file_length", "qty_dot_file", "qty_hyphen_file", "qty_underline_file",
    "params_length", "qty_params", "qty_dot_params", "qty_hyphen_params",
    "qty_underline_params", "qty_equal_params", "qty_and_params",
    "qty_ip_resolved", "qty_nameservers", "qty_mx_servers",
    "time_domain_activation", "time_domain_expiration", "tls_ssl_certificate",
    "time_response", "url_google_index"
]

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Cybersecurity API is Running!"})

@app.route("/extract_apt_data", methods=["GET"])
def extract_apt_data():
    try:
        # Initialize the NetworkFlowAnalyzer
        analyzer = NetworkFlowAnalyzer()
        
        # Capture packets (default 1000)
        packet_count = request.args.get('packet_count', default=1000, type=int)
        analyzer.capture_packets(count=packet_count)
        
        # Export to CSV and get the data
        flow_data = analyzer._calculate_flow_features()
        
        return jsonify({
            "message": "APT data extracted successfully",
            "data": flow_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/predict_apt", methods=["POST"])
def predict_apt():
    try:
        # Get JSON data from the request
        input_data = request.get_json()

        # Convert JSON data to DataFrame
        df_live = pd.DataFrame(input_data)

        # Convert IP addresses to numeric format
        if "Src IP" in df_live.columns and "Dst IP" in df_live.columns:
            df_live["Src IP"] = df_live["Src IP"].apply(ip_to_int)
            df_live["Dst IP"] = df_live["Dst IP"].apply(ip_to_int)

        # Handle missing values
        df_live.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_live.fillna(df_live.median(), inplace=True)

        # Select required features
        df_live = df_live[APT_SELECTED_FEATURES]

        # Normalize data
        X_live_scaled = apt_scaler.transform(df_live)

        # Make predictions
        predictions = apt_model.predict(X_live_scaled)
        decoded_predictions = apt_label_encoder.inverse_transform(predictions)

        return jsonify({
            "predictions": decoded_predictions.tolist(),
            "message": "APT detection completed successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/extract_url_features", methods=["POST"])
def extract_url_features():
    try:
        # Get URL from request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL not provided"}), 400

        url = data['url']

        # Extract features
        extractor = URLFeatureExtractor()
        features = extractor.extract_features(url)

        if not features:
            return jsonify({"error": "Failed to extract features"}), 400

        return jsonify({
            "url": url,
            "features": features,
            "message": "Features extracted successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/predict_phishing", methods=["POST"])
def predict_phishing():
    try:
        # Get JSON data from request
        data = request.get_json()

        # Convert to DataFrame
        df_real = pd.DataFrame([data])

        # Ensure correct feature order and missing values handling
        df_real = df_real.reindex(columns=PHISHING_FEATURES, fill_value=0)

        # Scale the input data
        X_real_scaled = phishing_scaler.transform(df_real)

        # Make prediction
        prediction = phishing_model.predict(X_real_scaled)
        probability = phishing_model.predict_proba(X_real_scaled)

        # Convert prediction back to label
        predicted_label = phishing_label_encoder.inverse_transform(prediction)[0]

        return jsonify({
            "prediction": predicted_label,
            "confidence": float(max(probability[0])),
            "message": "Prediction completed successfully"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/analyze_system_logs", methods=["POST"])
def analyze_system_logs():
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Get baseline and current log counts
        baseline_logs = data.get('baseline_logs', {})
        current_logs = data.get('current_logs', {})

        # Initialize results dictionary
        anomalies = {}
        
        # Calculate percentage changes for each log type
        for log_type in ['system', 'security', 'application', 'ssh', 'auth']:
            if log_type in baseline_logs and log_type in current_logs:
                baseline_count = baseline_logs[log_type]
                current_count = current_logs[log_type]
                
                if baseline_count > 0:  # Avoid division by zero
                    percent_change = ((current_count - baseline_count) / baseline_count) * 100
                    
                    # Flag significant increases (e.g., more than 50% increase)
                    if percent_change > 50:
                        anomalies[log_type] = {
                            'baseline_count': baseline_count,
                            'current_count': current_count,
                            'percent_increase': round(percent_change, 2)
                        }

        # Determine if potential APT activity based on anomalies
        apt_risk_level = 'LOW'
        if len(anomalies) >= 2:  # If multiple log types show anomalies
            apt_risk_level = 'HIGH'
        elif len(anomalies) == 1:
            apt_risk_level = 'MEDIUM'

        return jsonify({
            'apt_risk_level': apt_risk_level,
            'anomalies': anomalies,
            'message': 'Log analysis completed successfully'
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/extract_system_logs", methods=["GET"])
def extract_system_logs():
    try:
        # Get parameters from request
        hours = request.args.get('hours', default=24, type=int)  # Default to last 24 hours
        log_types = request.args.get('log_types', default='all')
        
        # Convert log_types to list if specified
        if log_types != 'all':
            log_types = log_types.split(',')
        
        # Calculate time threshold
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        # Initialize log collection
        logs = {
            'system': [],
            'security': [],
            'application': [],
            'ssh': [],
            'auth': []
        }
        
        # Windows Event Logs
        if os.name == 'nt':
            if log_types == 'all' or 'system' in log_types:
                try:
                    system_logs = subprocess.check_output(
                        ['wevtutil', 'qe', 'System', '/f:json', '/c:100'], 
                        shell=True
                    )
                    logs['system'] = json.loads(system_logs)
                except:
                    pass
                    
            if log_types == 'all' or 'security' in log_types:
                try:
                    security_logs = subprocess.check_output(
                        ['wevtutil', 'qe', 'Security', '/f:json', '/c:100'],
                        shell=True
                    )
                    logs['security'] = json.loads(security_logs)
                except:
                    pass
        else:
            if log_types == 'all' or 'auth' in log_types:
                try:
                    auth_logs = subprocess.check_output(
                        ['sudo', 'grep', '-a', f'"{time_threshold.strftime("%b %d")}"', '/var/log/auth.log'],
                        shell=True
                    )
                    logs['auth'] = auth_logs.decode().split('\n')
                except:
                    pass
                    
            if log_types == 'all' or 'system' in log_types:
                try:
                    system_logs = subprocess.check_output(
                        ['sudo', 'journalctl', '--since', f'{hours}h ago', '--output=json'],
                        shell=True
                    )
                    logs['system'] = [json.loads(line) for line in system_logs.decode().split('\n') if line]
                except:
                    pass
                    
            if log_types == 'all' or 'ssh' in log_types:
                try:
                    ssh_logs = subprocess.check_output(
                        ['sudo', 'grep', '-a', f'"{time_threshold.strftime("%b %d")}"', '/var/log/auth.log'],
                        shell=True
                    )
                    logs['ssh'] = [line for line in ssh_logs.decode().split('\n') if 'sshd' in line]
                except:
                    pass

        # Extract relevant APT indicators
        apt_indicators = {
            'failed_logins': 0,
            'suspicious_processes': 0,
            'network_connections': 0,
            'file_system_changes': 0,
            'privilege_escalations': 0
        }

        # Analyze logs for APT indicators
        for log_type, entries in logs.items():
            if not entries:
                continue
                
            for entry in entries:
                # Check for failed logins
                if any(indicator in str(entry).lower() for indicator in ['failed password', 'authentication failure']):
                    apt_indicators['failed_logins'] += 1
                
                # Check for suspicious processes
                if any(indicator in str(entry).lower() for indicator in ['cmd.exe', 'powershell', 'bash', 'suspicious']):
                    apt_indicators['suspicious_processes'] += 1
                
                # Check for network connections
                if any(indicator in str(entry).lower() for indicator in ['connection', 'network', 'port']):
                    apt_indicators['network_connections'] += 1
                
                # Check for file system changes
                if any(indicator in str(entry).lower() for indicator in ['created', 'modified', 'deleted', 'chmod']):
                    apt_indicators['file_system_changes'] += 1
                
                # Check for privilege escalations
                if any(indicator in str(entry).lower() for indicator in ['sudo', 'administrator', 'privilege']):
                    apt_indicators['privilege_escalations'] += 1

        return jsonify({
            "message": "System logs extracted successfully",
            "data": {
                "logs": logs,
                "apt_indicators": apt_indicators,
                "analysis_period": f"Last {hours} hours",
                "timestamp": datetime.now().isoformat()
            }
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "message": "Failed to extract system logs"
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)