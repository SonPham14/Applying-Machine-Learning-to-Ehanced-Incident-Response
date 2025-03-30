import joblib
import pandas as pd
import json
import subprocess
import requests
import os
import csv

# Định nghĩa đường dẫn tới mô hình ML và log
MODEL_PATH = "/Users/mac/Downloads/machinelearning-project/model/threat_detection.pkl"
LOG_FILE = "/Users/mac/Downloads/machinelearning-project/data/firewall_logs.csv"

# Kiểm tra mô hình tồn tại trước khi load
if not os.path.exists(MODEL_PATH):
    print("❌ LỖI: Không tìm thấy mô hình tại", MODEL_PATH)
    exit(1)

# Load mô hình ML đã huấn luyện
model = joblib.load(MODEL_PATH)

# URL API của SOAR (giả lập)
SOAR_API_URL = "http://127.0.0.1:5050/api/logs"
API_KEY = "test_api_key"

# Cập nhật danh sách feature
FEATURE_COLUMNS = [
    "bytes_sent", "bytes_received", "src_port", "dest_port", 
    "protocol", "threat_score", "is_internal_ip", "src_ip_reputation"
]

# ⚡ Hàm kiểm tra IP nội bộ
def is_internal(ip):
    return 1 if ip.startswith("192.168.") or ip.startswith("10.") else 0

# ⚡ Hàm lấy danh tiếng IP
def get_ip_reputation(ip):
    bad_ips = {"203.0.113.5": 100, "192.168.1.10": 30}
    return bad_ips.get(ip, 10)

# ⚡ Hàm phân tích đe dọa
def analyze_threat(log_entry):
    log_entry["is_internal_ip"] = is_internal(log_entry.get("src_ip", "0.0.0.0"))
    log_entry["src_ip_reputation"] = get_ip_reputation(log_entry.get("src_ip", "0.0.0.0"))
    
    filtered_log = {key: log_entry[key] for key in FEATURE_COLUMNS if key in log_entry}
    df = pd.DataFrame([filtered_log])
    
    try:
        prediction = model.predict(df)  # Kiểm tra output
        is_threat, recommended_action = prediction[0]
    except Exception as e:
        print("❌ LỖI DỰ ĐOÁN:", e)
        return {"is_threat": False, "recommended_action": "Khong co hanh dong"}
    
    # Kết hợp với threat_score
    if log_entry["threat_score"] > 80:
        recommended_action = 1  # Chặn IP
    elif 50 <= log_entry["threat_score"] <= 80:
        recommended_action = 2  # Cách ly Endpoint
    else:
        recommended_action = 0  # Không có hành động nào
    
    actions = {0: "Khong co hanh dong", 1: "IP Blocked", 2: "Endpoint isolation"}
    return {"is_threat": bool(is_threat), "recommended_action": actions.get(recommended_action, "Khong co hanh dong")}

# ⚡ Hàm lưu log vào CSV
def save_log_to_csv(log_entry, prediction):
    file_exists = os.path.exists(LOG_FILE)
    log_data = [
        log_entry["bytes_sent"], log_entry["bytes_received"], log_entry["src_port"],
        log_entry["dest_port"], log_entry["protocol"], log_entry["threat_score"],
        log_entry["is_internal_ip"], log_entry["src_ip_reputation"],
        int(prediction["is_threat"]),
        1 if prediction["recommended_action"] == "IP Blocked" else 2 if prediction["recommended_action"] == "Endpoint isolation" else 0
    ]
    
    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        if not file_exists or os.stat(LOG_FILE).st_size == 0:
            writer.writerow(FEATURE_COLUMNS + ["is_threat", "recommended_action"])
        writer.writerow(log_data)

# ⚡ Hàm thực thi hành động
def execute_action(action, log_entry):
    if action == "IP Blocked":
        ip_to_block = log_entry.get("src_ip", "0.0.0.0")
        print("🚨 IP Blocked:", ip_to_block)
        if os.geteuid() != 0:
            print("⚠️ Không có quyền root để chặn IP!")
        else:
            subprocess.run(["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip_to_block])
    elif action == "Endpoint isolation":
        endpoint_id = log_entry.get("endpoint_id", "UNKNOWN")
        print("🔒 Endpoint isolation:", endpoint_id)
        subprocess.run(["echo", f"Quarantine {endpoint_id}"])

# ⚡ Chương trình chính
if __name__ == "__main__":
    print("🚀 Đang xử lý các log từ file CSV...")
    try:
        if os.stat(LOG_FILE).st_size == 0:
            print("⚠️ File CSV rỗng, không có log để xử lý!")
        else:
            logs = pd.read_csv(LOG_FILE, on_bad_lines='skip')  # Đọc log từ file CSV và bỏ qua dòng lỗi
            print(f"✅ Đọc được {len(logs)} log từ file CSV")
            
            for _, log_data in logs.iterrows():
                log_entry = log_data.to_dict()  # Chuyển mỗi dòng thành dict
                print("\n📌 Phân tích log:", json.dumps(log_entry, indent=4))
                result = analyze_threat(log_entry)
                print(f"✅ Phân tích hoàn thành: {json.dumps(result, indent=4)}")
                save_log_to_csv(log_entry, result)
                if result["is_threat"]:
                    execute_action(result["recommended_action"], log_entry)
                    
    except Exception as e:
        print(f"❌ LỖI ĐỌC FILE CSV: {e}")
