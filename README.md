<p align="center">
  <h1 align="center">🛡️ Enterprise UEBA dựa trên Trí tuệ Nhân tạo (AI-Driven Enterprise UEBA)</h1>
  <p align="center">
    <strong>Hệ thống Phát hiện Mối đe dọa Nội bộ (Insider Threat Detection) &amp; Phân tích Thời gian thực (Real-time SOC)</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/scikit--learn-1.4.0-F7931E?logo=scikit-learn&logoColor=white" alt="scikit-learn" />
    <img src="https://img.shields.io/badge/Flask-3.0%2B-000?logo=flask&logoColor=white" alt="Flask" />
    <img src="https://img.shields.io/badge/Socket.IO-Real--time-010101?logo=socket.io&logoColor=white" alt="Socket.IO" />
    <img src="https://img.shields.io/badge/Plotly.js-2.32-3F4F75?logo=plotly&logoColor=white" alt="Plotly.js" />
  </p>
</p>

---

## 📋 Mục tiêu & Tóm tắt Dự án

**UEBA (User and Entity Behavior Analytics)** là thành phần then chốt trong các Trung tâm Giám sát An ninh mạng (SOC). Các công cụ SIEM truyền thống dựa trên luật thường tạo ra nhiều cảnh báo giả. 

Dự án này cung cấp một **Pipeline Phân tích Hành vi Liên kết Đa nguồn Nhật ký** sử dụng Học máy không giám sát. Phiên bản mới nhất nâng cấp hệ thống từ xử lý Batch (tĩnh) sang kiến trúc **2 Giai đoạn (Offline Profiling & Online Detection)** — thiết kế chuẩn mực của các hệ thống SIEM doanh nghiệp lớn, giúp xử lý khối lượng log khổng lồ mà không gây nghẽn CPU/RAM.

---

## ✨ Các tính năng nổi bật mới nhất

- **Kiến trúc 2 Giai đoạn chuẩn Enterprise**: 
  - **Offline Profiling**: Định kỳ học hỏi "thói quen" bình thường từ dữ liệu lịch sử lớn và lưu **Profile Baseline** xuống Database.
  - **Online Detection**: Chạy nền (daemon) 24/7, tiêu tốn cực ít RAM, giám sát dòng log mới và đối chiếu ngay lập tức với Baseline.
- **Real-time SOC Dashboard**: Cảnh báo (Alerts) được đẩy về trình duyệt ngay lập tức (độ trễ mili-giây) thông qua **WebSockets (Flask-SocketIO)** mà không cần tải lại trang.
- **Log Simulator đi kèm**: Tích hợp sẵn bộ giả lập sinh log hệ thống liên tục và tự động tiêm (inject) các hành vi tấn công (ví dụ: đăng nhập nhiều nửa đêm, tải file nhạy cảm) để dễ dàng demo hệ thống cảnh báo.
- **Khả năng giải thích (Explainability)**: Khi có cảnh báo, hệ thống chỉ rõ đặc trưng nào (ví dụ: số email ngoài, tải file zip) đang lệch chuẩn bao nhiêu Sigma (σ) so với bình thường.

---

## 🏗️ Kiến trúc Hệ thống 2 Giai đoạn

Vì việc chạy mô hình Học máy phức tạp trực tiếp trên từng dòng log thô của 1000+ máy trạm theo thời gian thực là bất khả thi về mặt tài nguyên, dự án chia làm hai luồng riêng biệt:

```text
┌─────────────────────────────────────────────────────────────┐
│  GIAI ĐOẠN 1: OFFLINE PROFILING (Định kỳ ban đêm)          │
│                                                             │
│  Log lịch sử (CSV) → src/offline_profiler.py → Train ML    │
│    → Export model (joblib) + Lưu Profile Baseline vào SQLite│
└─────────────────────────────────────────────────────────────┘
                           ↓ Baseline DB (baseline.db)
┌─────────────────────────────────────────────────────────────┐
│  GIAI ĐOẠN 2: ONLINE DETECTION (Chạy liên tục 24/7)        │
│                                                             │
│  Log mới đổ về → src/online_detector.py → Sliding Window   │
│    → Feature Vector → So sánh nhanh vs Baseline            │
│    → Deviation Score > threshold → Cảnh báo nguy hiểm      │
│    → WebSocket → Cập nhật lên Dashboard SOC                │
└─────────────────────────────────────────────────────────────┘
```

### 8 Đặc trưng hành vi được trích xuất (Feature Engineering)

| # | Đặc trưng | Mô tả |
|---|---|---|
| 1 | `total_logins` | Tổng số lần đăng nhập vào hệ thống |
| 2 | `off_hour_logins` | Số lần đăng nhập ngoài giờ hành chính (trước 07:00 / sau 18:00) |
| 3 | `total_usb_connects` | Tổng số lần kết nối thiết bị USB |
| 4 | `off_hour_usb` | Số lần cắm USB ngoài giờ làm việc |
| 5 | `total_emails` | Tổng số email được gửi |
| 6 | `external_emails` | Số email gửi đến địa chỉ ngoài tên miền doanh nghiệp |
| 7 | `total_file_access` | Tổng số thao tác truy cập tệp |
| 8 | `exe_zip_downloads` | Số lần thao tác trên tệp `.exe` / `.zip` |

---

## 📂 Cấu trúc dự án

```text
ueba-insider-threat/
├── data/
│   ├── baseline.db              # [MỚI] SQLite DB lưu Profile Baseline
│   ├── alerts.db                # [MỚI] SQLite DB lưu lịch sử cảnh báo
│   ├── live_logs/system.log     # [MỚI] File log thời gian thực
│   └── logon.csv, device.csv... # Log tĩnh lịch sử cho Profiling
├── models/                      # [MỚI] Nơi lưu mô hình (.joblib)
├── src/
│   ├── offline_profiler.py      # [MỚI] Script chạy Giai đoạn 1 (Offline)
│   ├── online_detector.py       # [MỚI] Engine giám sát Giai đoạn 2 (Online)
│   ├── log_simulator.py         # [MỚI] Giả lập sinh log hệ thống để demo
│   ├── ueba_pipeline.py         # Core Pipeline ML (Gom cụm & Isolation Forest)
│   ├── web_app.py               # Flask Web Server (REST + WebSocket)
│   ├── templates/index.html     # Giao diện SOC Dashboard
│   └── static/style.css         # CSS Dark Mode
└── requirements.txt
```

---

## 🚀 Hướng dẫn Cài đặt & Chạy Thực tế

### 1. Chuẩn bị môi trường
```bash
git clone https://github.com/your-username/ueba-insider-threat.git
cd ueba-insider-threat
python -m venv .venv

# Kích hoạt môi trường (Windows)
.venv\Scripts\activate

# Cài đặt thư viện
pip install -r requirements.txt
```

### 2. Bước 1: Tạo Baseline Profile (Offline Profiling)
Phải chạy bước này để hệ thống "học" thói quen bình thường của user từ file CSV cũ:
```bash
python src/offline_profiler.py
```
*Lưu ý: Mô hình sẽ được xuất ra `models/` và hồ sơ lưu vào `data/baseline.db`.*

### 3. Bước 2: Khởi động Web Dashboard & Online Detector
```bash
python src/web_app.py
```
Hệ thống sẽ chạy tại địa chỉ **http://127.0.0.1:5000**.
Truy cập trình duyệt, bạn sẽ thấy 2 Tab: **Lịch sử (Batch)** và **Real-time SOC Monitor**. Engine `OnlineDetector` sẽ tự động chạy ngầm bên trong Flask.

### 4. Bước 3: Kích hoạt Sinh log giả lập (Simulator)
Mở một Terminal khác, chạy Script giả lập để liên tục đẩy dòng log mới vào hệ thống:
```bash
python src/log_simulator.py
```
Lúc này, quay lại trình duyệt ở tab **Real-time SOC Monitor**, bạn sẽ thấy các tín hiệu cảnh báo nhảy tự động trên màn hình mà không cần f5 tải trang.

---

## 📊 Hướng dẫn đọc Dashboard

### Tab 1: Phân tích Lịch sử (Batch)
- Hiển thị lại toàn bộ dữ liệu lịch sử dưới dạng Biểu đồ tương tác Plotly.js.
- **PCA Scatter Plot**: Phân cụm 2 chiều, điểm đỏ là các User bất thường.
- **Radar Chart**: So sánh chi tiết đa chiều thói quen của Top-5 nghi phạm so với mức trung bình.
- **Heatmap**: Tương quan giữa các hành vi (Ví dụ: Hay cắm USB ngoài giờ có đi liền với gửi email ra ngoài?).

### Tab 2: Real-time SOC Monitor (Giám sát Thời gian thực)
- **Live Alert Feed**: Luồng cảnh báo trực tiếp qua WebSocket. Bất cứ khi nào hệ thống phát hiện hành vi lệch chuẩn, một dòng cảnh báo sẽ nhảy lên đầu bảng.
- **Chi tiết sai lệch (Deviation)**: Phân tích tại sao ML ra quyết định cảnh báo (Ví dụ: `total_emails: 80 (Mean: 20, Dev: 4.5σ)` - gửi nhiều gấp 4.5 lần độ lệch chuẩn).

---

## 🔬 Tùy biến cho Môi trường Doanh nghiệp Thật

Hệ thống được thiết kế mở để dễ dàng nâng cấp khi đưa vào Production:
1. **Thay thế SQLite bằng Redis**: Trong `online_detector.py`, hàm `update_state` hiện đang lưu State vào Memory của Python/SQLite. Để Scale nhiều node, hãy thay bằng Redis Hash.
2. **Nguồn Log Ingestion**: Đổi `log_simulator.py` thành công cụ cấu hình Logstash/Fluentd, đẩy trực tiếp từ Kafka hoặc đọc Syslog.
3. **Training Định kỳ**: Đặt cronjob gọi `python src/offline_profiler.py` chạy lúc 2h sáng mỗi Chủ Nhật.

---

## 📝 Giấy phép

Dự án được cấp phép theo **Giấy phép MIT**. Phục vụ mục đích nghiên cứu SOC, SIEM và bảo mật dữ liệu doanh nghiệp.
