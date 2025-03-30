import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import accuracy_score
from imblearn.over_sampling import SMOTE

# 🔹 Bước 1: Đọc dữ liệu
DATA_PATH = "/Users/mac/Downloads/machinelearning-project/data/firewall_logs.csv"

def load_data(path):
    try:
        df = pd.read_csv(path, on_bad_lines='skip')
        print("✅ Đọc dữ liệu thành công!")
        return df
    except Exception as e:
        print("❌ Lỗi đọc file:", e)
        exit(1)

df = load_data(DATA_PATH)

# 🔹 Kiểm tra giá trị NaN
print("🔍 Kiểm tra dữ liệu bị thiếu:\n", df.isna().sum())

# 🔹 Xử lý cột `recommended_action`
action_mapping = {"Không có hành động": 0, "Chặn IP": 1, "Cách ly endpoint": 2}
df['recommended_action'] = df['recommended_action'].map(action_mapping).fillna(0).astype(int)

# 🔹 Thêm các feature mới
df["is_internal_ip"] = df["src_ip"].apply(lambda ip: 1 if str(ip).startswith(("192.168.", "10.")) else 0)
df["src_ip_reputation"] = df["src_ip"].apply(lambda ip: np.random.randint(1, 101))  # Giá trị ngẫu nhiên 1-100

# 🔹 Cập nhật danh sách features
FEATURE_COLUMNS = ['bytes_sent', 'bytes_received', 'src_port', 'dest_port', 
                   'protocol', 'threat_score', 'is_internal_ip', 'src_ip_reputation']
X = df[FEATURE_COLUMNS]
y = df[['is_threat', 'recommended_action']]

# 📊 Kiểm tra tính đa dạng của dữ liệu
print("📊 Phân phối dữ liệu:")
print("is_threat:")
print(y["is_threat"].value_counts())
print("recommended_action:")
print(y["recommended_action"].value_counts())

# 💊 Xử lý mất cân bằng dữ liệu
if y['is_threat'].nunique() > 1 and y['recommended_action'].nunique() > 1:
    smote = SMOTE(random_state=42, k_neighbors=1)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    print("✅ SMOTE thành công!")
else:
    print("⚠️ Không thể áp dụng SMOTE! Tạo thêm dữ liệu ngẫu nhiên...")
    extra_samples = 10
    extra_X = X.sample(extra_samples, replace=True, random_state=42).reset_index(drop=True)
    extra_y = y.sample(extra_samples, replace=True, random_state=42).reset_index(drop=True)
    X_resampled = pd.concat([X, extra_X], ignore_index=True)
    y_resampled = pd.concat([y, extra_y], ignore_index=True)

# 🔹 Bước 3: Chia tập train/test
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.2, random_state=42)

# 🔹 Bước 4: Huấn luyện mô hình
base_model = RandomForestClassifier(n_estimators=100, max_depth=10, class_weight="balanced", random_state=42)
model = MultiOutputClassifier(base_model)
model.fit(X_train, y_train)

# 🔹 Bước 5: Dự đoán và đánh giá
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 Độ chính xác của mô hình: {accuracy * 100:.2f}%")

# 🔹 Ghi log chi tiết
print("📊 Kiểm tra phân phối dự đoán:")
print(pd.DataFrame(y_pred, columns=['is_threat_pred', 'recommended_action_pred']).value_counts())

# 🔹 Bước 6: Lưu mô hình
MODEL_PATH = "/Users/mac/Downloads/machinelearning-project/model/threat_detection.pkl"
joblib.dump(model, MODEL_PATH)
print("✅ Mô hình đã được lưu tại:", MODEL_PATH)
