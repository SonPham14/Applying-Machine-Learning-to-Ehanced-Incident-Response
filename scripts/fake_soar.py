from flask import Flask, jsonify, request

app = Flask(__name__)

# API giả lập trả về log mẫu
@app.route('/api/logs', methods=['GET'])
def get_logs():
    api_key = request.headers.get("API-Key")
    if api_key != "test_api_key":
        return jsonify({"error": "Forbidden"}), 403  # Lỗi 403 nếu API Key sai

    logs = [
        {
            "bytes_sent": 70000,
            "bytes_received": 30000,
            "src_ip": "192.168.1.10",
            "src_port": 22,
            "dest_port": 3389,
            "protocol": 6,
            "threat_score": 95
        }
    ]
    return jsonify(logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
