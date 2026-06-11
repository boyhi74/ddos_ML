# 🛡️ Hệ thống Phát hiện và Phòng chống DDoS bằng Machine Learning

## 📌 Tổng quan
Dự án này là một hệ thống bảo mật tự động được thiết kế để phát hiện và ngăn chặn các cuộc tấn công từ chối dịch vụ phân tán (DDoS) theo thời gian thực. Hệ thống áp dụng cơ chế phát hiện kép: kết hợp giữa kiểm tra ngưỡng động (dynamic thresholds) để bắt các cuộc tấn công phổ biến, và mô hình Machine Learning (Random Forest) để nhận diện các mẫu lưu lượng tấn công phức tạp.

## ✨ Tính năng nổi bật
* **Thu thập lưu lượng trực tiếp (Real-time Sniffing):** Sử dụng Scapy để bắt các gói tin TCP, UDP, ICMP trực tiếp trên giao diện mạng (ví dụ: `ens33`).
* **Phát hiện đa lớp (Hybrid Detection):** * *Dựa trên ngưỡng:* Xử lý nhanh các tấn công SYN Flood, UDP Flood và Amplification (NetBIOS, LDAP).
  * *Dựa trên AI:* Sử dụng thuật toán Random Forest phân loại các hành vi bất thường tinh vi.
* **Ngăn chặn tự động (Automated Mitigation):** Lập tức đưa IP tấn công vào Blacklist và thực thi lệnh chặn cấp hệ thống thông qua `iptables`.
* **Cảnh báo qua Telegram:** Ghi nhận log chi tiết và tự động đẩy cảnh báo (Alerts) thời gian thực đến quản trị viên thông qua Telegram Bot.

## 🛠️ Công nghệ sử dụng
* **Ngôn ngữ:** Python 3.8.
* **Machine Learning & Xử lý dữ liệu:** Scikit-learn, Pandas, NumPy, Joblib.
* **Xử lý mạng:** Scapy.
* **Hệ thống & Tường lửa:** Ubuntu 22.04 LTS, `iptables`.
* **Thông báo:** API Telegram Bot (`python-telegram-bot`).

## 🚀 Luồng hoạt động (Architecture)
1. **Thu thập dữ liệu:** Scapy liên tục lắng nghe và thu thập lưu lượng mạng theo từng chu kỳ.
2. **Trích xuất đặc trưng:** Dữ liệu thô được chuyển đổi thành các thông số kỹ thuật (Flow Duration, Flow Packets/s, Total Fwd Packets...).
3. **Phân tích:** Dữ liệu đi qua bộ lọc ngưỡng, nếu an toàn sẽ tiếp tục được mô hình Random Forest phân tích.
4. **Hành động:** Nếu xác định là tấn công, hệ thống gọi `iptables` để drop IP nguồn.
5. **Giám sát:** Ghi log sự kiện và gửi cảnh báo đến Telegram.

## ⚙️ Hướng dẫn cài đặt
### 1. Yêu cầu hệ thống
* Hệ điều hành: Linux (Khuyến nghị Ubuntu 20.04/22.04).
* Yêu cầu quyền `root` (sudo) để can thiệp `iptables` và bắt gói tin mạng.

### 2. Cài đặt thư viện
```bash
# Cập nhật hệ thống và cài đặt công cụ cần thiết
sudo apt update
sudo apt install python3-pip net-tools iptables -y

# Cài đặt các thư viện Python
pip3 install scapy pandas numpy scikit-learn joblib python-telegram-bot
