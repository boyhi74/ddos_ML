# 🛡️ Hệ thống Phát hiện và Phòng chống DDoS bằng Machine Learning

## 📌 Tổng quan
]Dự án này là một hệ thống bảo mật tự động được thiết kế để phát hiện và ngăn chặn các cuộc tấn công từ chối dịch vụ phân tán (DDoS) theo thời gian thực[cite: 520]. [cite_start]Hệ thống áp dụng cơ chế phát hiện kép: kết hợp giữa kiểm tra ngưỡng động (dynamic thresholds) để bắt các cuộc tấn công phổ biến, và mô hình Machine Learning (Random Forest) để nhận diện các mẫu lưu lượng tấn công phức tạp[cite: 558, 569, 570].

## ✨ Tính năng nổi bật
* **Thu thập lưu lượng trực tiếp (Real-time Sniffing):** Sử dụng Scapy để bắt các gói tin TCP, UDP, ICMP trực tiếp trên giao diện mạng (ví dụ: `ens33`)[cite: 563, 581].
* **Phát hiện đa lớp (Hybrid Detection):** * *Dựa trên ngưỡng:* Xử lý nhanh các tấn công SYN Flood, UDP Flood và Amplification (NetBIOS, LDAP)[cite: 528, 802].
  * [cite_start]*Dựa trên AI:* Sử dụng thuật toán Random Forest phân loại các hành vi bất thường tinh vi[cite: 530, 803].
* [cite_start]**Ngăn chặn tự động (Automated Mitigation):** Lập tức đưa IP tấn công vào Blacklist và thực thi lệnh chặn cấp hệ thống thông qua `iptables`[cite: 572, 573, 804].
* [cite_start]**Cảnh báo qua Telegram:** Ghi nhận log chi tiết và tự động đẩy cảnh báo (Alerts) thời gian thực đến quản trị viên thông qua Telegram Bot[cite: 575, 576, 619].

## 🛠️ Công nghệ sử dụng
* [cite_start]**Ngôn ngữ:** Python 3.8[cite: 627].
* [cite_start]**Machine Learning & Xử lý dữ liệu:** Scikit-learn, Pandas, NumPy, Joblib[cite: 630, 631, 649, 653].
* [cite_start]**Xử lý mạng:** Scapy[cite: 629].
* [cite_start]**Hệ thống & Tường lửa:** Ubuntu 22.04 LTS, `iptables`[cite: 634, 639].
* [cite_start]**Thông báo:** API Telegram Bot (`python-telegram-bot`)[cite: 632].

## 🚀 Luồng hoạt động (Architecture)
1. [cite_start]**Thu thập dữ liệu:** Scapy liên tục lắng nghe và thu thập lưu lượng mạng theo từng chu kỳ[cite: 556].
2. [cite_start]**Trích xuất đặc trưng:** Dữ liệu thô được chuyển đổi thành các thông số kỹ thuật (Flow Duration, Flow Packets/s, Total Fwd Packets...)[cite: 526, 566].
3. [cite_start]**Phân tích:** Dữ liệu đi qua bộ lọc ngưỡng, nếu an toàn sẽ tiếp tục được mô hình Random Forest phân tích[cite: 558].
4. [cite_start]**Hành động:** Nếu xác định là tấn công, hệ thống gọi `iptables` để drop IP nguồn[cite: 559].
5. [cite_start]**Giám sát:** Ghi log sự kiện và gửi cảnh báo đến Telegram[cite: 560].

## ⚙️ Hướng dẫn cài đặt
### 1. Yêu cầu hệ thống
* [cite_start]Hệ điều hành: Linux (Khuyến nghị Ubuntu 20.04/22.04)[cite: 546, 639].
* [cite_start]Yêu cầu quyền `root` (sudo) để can thiệp `iptables` và bắt gói tin mạng[cite: 656, 807].

### 2. Cài đặt thư viện
```bash
# Cập nhật hệ thống và cài đặt công cụ cần thiết
sudo apt update
sudo apt install python3-pip net-tools iptables -y

# Cài đặt các thư viện Python
pip3 install scapy pandas numpy scikit-learn joblib python-telegram-bot
### 2. Cài đặt thư viện
Mở tệp mã nguồn và cấu hình lại tên giao diện mạng của bạn (ví dụ: ens33, eth0)
Cấu hình Telegram Bot Token và Chat ID để nhận cảnh báo.
