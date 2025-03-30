import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import json

def preprocess_data(json_data):
    df = pd.DataFrame(json.loads(json_data))

    # Giả sử chỉ dùng 'bytes_sent' và 'bytes_received' làm đầu vào
    X = df[['bytes_sent', 'bytes_received']]

    # Chuẩn hóa dữ liệu
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Lưu scaler để dùng trong dự đoán
    joblib.dump(scaler, 'models/scaler.pkl')

    return X_scaled
