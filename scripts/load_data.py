import pandas as pd
import json

def load_data_from_csv():
    return pd.read_csv("data/data.csv")

def load_data_from_json(json_data):
    return pd.DataFrame(json.loads(json_data))

# Ví dụ: nhận dữ liệu từ SOAR JSON
json_log = '{"src_ip": "192.168.1.10", "dest_ip": "8.8.8.8", "bytes_sent": 50000, "bytes_received": 20000}'
df = load_data_from_json(json_log)
print(df)
