import joblib
import pandas as pd

# Load mô hình đã huấn luyện
model = joblib.load("/Users/mac/Downloads/machinelearning-project/model/threat_detection.pkl")

# Dữ liệu log cần dự đoán (đây là ví dụ, sẽ thay bằng dữ liệu thật từ SOAR)
log_data = {
    "bytes_sent": 50000,
    "bytes_received": 20000,
    "src_port": 443,
    "dest_port": 8080,
    "protocol": 6,
    "threat_score": 85
}

# Chuyển dữ liệu thành DataFrame
df = pd.DataFrame([log_data])

# Dự đoán
prediction = model.predict(df)
is_threat, recommended_action = prediction[0]

# In kết quả
actions = {0: "Không có hành động", 1: "Chặn IP", 2: "Cách ly endpoint"}
print(f"🔍 Dự đoán: {'CÓ' if is_threat else 'KHÔNG'} mối đe dọa")
print(f"🚨 Hành động đề xuất: {actions[recommended_action]}")
