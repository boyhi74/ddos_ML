import pandas as pd
import numpy as np
import os
import joblib
from joblib import Parallel, delayed
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# 📂 1️⃣ Đọc nhiều file CSV nhanh hơn
folder_path = r"D:\down\03-11"  
file_list = ["Syn.csv", "UDP.csv"]  

def load_csv(file):
    file_path = os.path.join(folder_path, file)
    if os.path.exists(file_path):
        print(f"📂 Đang đọc: {file}...")
        df = pd.read_csv(file_path, low_memory=False).dropna()  # Loại bỏ dòng trống ngay lập tức
        df.columns = df.columns.str.strip()  # Xóa khoảng trắng trong tên cột
        df["source_file"] = file  
        return df
    else:
        print(f"⚠️ Không tìm thấy file: {file}")
        return None

# Sử dụng đa luồng để đọc file nhanh hơn
df_list = Parallel(n_jobs=-1)(delayed(load_csv)(file) for file in file_list)
df = pd.concat([d for d in df_list if d is not None], ignore_index=True)

if df.empty:
    raise ValueError("❌ Không có dữ liệu hợp lệ!")

# 📊 2️⃣ Kiểm tra dữ liệu
print("📊 Thông tin dữ liệu:")
print(df.info())

# 📌 3️⃣ Xử lý dữ liệu trống & loại bỏ cột không cần thiết
df.dropna(inplace=True)

# 📌 4️⃣ Mã hóa nhãn (Label Encoding)
if 'Label' not in df.columns:
    raise ValueError("❌ Cột 'Label' không tồn tại trong dữ liệu!")
    
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])

# 📌 5️⃣ Chọn cột số để làm feature (X)
numeric_columns = df.select_dtypes(include=[np.number]).columns.tolist()
df[numeric_columns] = df[numeric_columns].astype(np.float32)  # Tiết kiệm RAM

# 📌 6️⃣ Xử lý giá trị vô hạn trước khi chuẩn hóa
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Tách X và y
X = df[numeric_columns]
y = df['Label']

# 📌 7️⃣ Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 📌 8️⃣ Chia tập train & test
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# 📌 9️⃣ Huấn luyện mô hình Random Forest
print("🚀 Đang huấn luyện mô hình...")
model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 📌 🔟 Dự đoán & đánh giá mô hình
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 Độ chính xác mô hình: {accuracy:.4f}")
print(classification_report(y_test, y_pred))

# 📌 🔥 Lưu mô hình & scaler
joblib.dump(model, "ddos_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
print("✅ Mô hình đã được lưu thành công!")