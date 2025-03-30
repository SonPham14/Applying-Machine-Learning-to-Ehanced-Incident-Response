from flask import Flask, request, jsonify
import joblib
import numpy as np
import logging

# Cấu hình logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Tải mô hình và scaler
model_threat = joblib.load("models/threat_model.pkl")
model_action = joblib.load("models/action_model.pkl")
scaler = joblib.load("models/scaler.pkl")

app = Flask(__name__)

# API nhận log từ SOAR và dự đoán
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        logging.info(f"Received log: {data}")

        # Chuyển dữ liệu JSON thành mảng numpy
        features = np.array([
            data["bytes_sent"], data["bytes_received"], data["src_port"], data["dest_port"], data["protocol"], data["threat_score"]
        ]).reshape(1, -1)

        # Chuẩn hóa dữ liệu
        features_scaled = scaler.transform(features)

        # Dự đoán mối đe dọa
        threat_prediction = model_threat.predict(features_scaled)[0]

        # Nếu có đe dọa, dự đoán phản ứng phù hợp
        action_prediction = None
        if threat_prediction == 1:
            action_prediction = model_action.predict(features_scaled)[0]

        # Chuyển đổi mã phản ứng thành hành động cụ thể
        actions = {0: "Cảnh báo", 1: "Chặn IP", 2: "Cách ly endpoint"}
        action_text = actions.get(action_prediction, "Không có hành động")

        response = {
            "threat_detected": bool(threat_prediction),
            "recommended_action": action_text
        }

        logging.info(f"Prediction Result: {response}")
        return jsonify(response)

    except Exception as e:
        logging.error(f"Error during prediction: {str(e)}")
        return jsonify({"error": "Prediction failed"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
