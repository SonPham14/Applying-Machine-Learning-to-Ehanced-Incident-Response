import subprocess
import os
import time

# Định nghĩa đường dẫn file
TRAIN_SCRIPT = "/Users/mac/Downloads/machinelearning-project/scripts/train_model.py"
SOAR_SCRIPT = "/Users/mac/Downloads/machinelearning-project/scripts/soar_integration.py"
LOG_FILE = "auto_runner.log"

# ⚡ Hàm chạy lệnh và ghi log
def run_script(script_name):
    print(f"🚀 Đang chạy {script_name}...")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"\n🕒 {time.strftime('%Y-%m-%d %H:%M:%S')} - Chạy {script_name}\n")
        process = subprocess.run(["python3", script_name], stdout=log_file, stderr=log_file)
        if process.returncode == 0:
            print(f"✅ {script_name} chạy thành công!")
        else:
            print(f"❌ Lỗi khi chạy {script_name}. Xem {LOG_FILE} để biết chi tiết.")

# ⚡ Kiểm tra sự tồn tại của file mô hình trước và sau khi train
MODEL_PATH = "/Users/mac/Downloads/machinelearning-project/model/threat_detection.pkl"

def check_model_exists():
    return os.path.exists(MODEL_PATH)

# ⚡ Chạy quy trình tự động
if __name__ == "__main__":
    print("🔄 Bắt đầu quá trình tự động hóa...")
    
    # 1️⃣ Kiểm tra và huấn luyện lại mô hình
    before_train = check_model_exists()
    run_script(TRAIN_SCRIPT)
    after_train = check_model_exists()

    if not after_train:
        print("❌ Mô hình không tồn tại sau khi train. Dừng quá trình!")
        exit(1)
    
    if not before_train:
        print("✅ Mô hình mới đã được tạo.")
    else:
        print("✅ Mô hình đã được cập nhật.")

    # 2️⃣ Chạy xử lý log sau khi mô hình cập nhật
    run_script(SOAR_SCRIPT)

    print("🎯 Quá trình tự động hoàn tất! Xem log trong", LOG_FILE)
