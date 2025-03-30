import pandas as pd

# Định nghĩa các cột mong đợi
columns = [
    "bytes_sent", "bytes_received", "src_port", "dest_port", 
    "protocol", "threat_score", "is_internal_ip", "src_ip_reputation", "is_threat", "recommended_action"
]

# Đọc file dữ liệu
file_path = "/Users/mac/Downloads/machinelearning-project/data/firewall_logs_cleaned.csv"
try:
    df = pd.read_csv(file_path, on_bad_lines='warn', delimiter=',')  # Cảnh báo dòng lỗi thay vì dừng chương trình
except Exception as e:
    print(f"❌ LỖI ĐỌC FILE: {e}")
    exit(1)

# Kiểm tra số lượng cột
if df.shape[1] != len(columns):
    print(f"⚠️ CẢNH BÁO: Số lượng cột trong dữ liệu ({df.shape[1]}) không khớp với mong đợi ({len(columns)}). Đang cố gắng sửa...")
    df = df.iloc[:, :len(columns)]  # Chỉ giữ lại số cột cần thiết
    df.columns = columns[:df.shape[1]]  # Gán tên cột đúng

# Xử lý giá trị thiếu
df.fillna(0, inplace=True)

# Chuyển đổi cột 'recommended_action' về dạng số
action_mapping = {"Không có hành động": 0, "Chặn IP": 1, "Cách ly endpoint": 2}
df['recommended_action'] = df['recommended_action'].map(action_mapping).fillna(0).astype(int)

# Lưu file đã chỉnh sửa
df.to_csv("/Users/mac/Downloads/machinelearning-project/data/firewall_logs_cleaned.csv", index=False)
print("✅ File firewall_logs_cleaned.csv đã được cập nhật và làm sạch!")
