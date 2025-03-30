import pandas as pd

# Đọc dữ liệu
df = pd.read_csv("/Users/mac/Downloads/machinelearning-project/data/firewall_logs.csv")

# Thống nhất quy tắc:
# Nếu threat_score >= 90 thì recommended_action = 2 (Cách ly endpoint)
df.loc[df["threat_score"] >= 90, "recommended_action"] = 2

# Lưu lại file CSV
df.to_csv("/Users/mac/Downloads/machinelearning-project/data/firewall_logs.csv", index=False)

print("✅ Đã chuẩn hóa dữ liệu huấn luyện!")
