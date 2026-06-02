<p align="center">
  <h1 align="center">🛡️ Enterprise UEBA dựa trên Trí tuệ Nhân tạo (AI-Driven Enterprise UEBA)</h1>
  <p align="center">
    <strong>Hệ thống Phát hiện Mối đe dọa Nội bộ (Insider Threat Detection) &amp; Liên kết Đa nhật ký bằng Học máy</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/scikit--learn-1.4.0-F7931E?logo=scikit-learn&logoColor=white" alt="scikit-learn" />
    <img src="https://img.shields.io/badge/Flask-3.0%2B-000?logo=flask&logoColor=white" alt="Flask" />
    <img src="https://img.shields.io/badge/Plotly.js-2.32-3F4F75?logo=plotly&logoColor=white" alt="Plotly.js" />
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" />
  </p>
</p>

---

## 📋 Mục tiêu & Tóm tắt Dự án

**UEBA (User and Entity Behavior Analytics)** là thành phần then chốt trong các Trung tâm Giám sát An ninh mạng (SOC). Các công cụ SIEM truyền thống dựa trên luật thường tạo ra nhiều cảnh báo giả do phân tích từng nguồn nhật ký độc lập.

Dự án này cung cấp một **Pipeline Phân tích Hành vi Liên kết Đa nguồn Nhật ký** sử dụng Học máy không giám sát. Hệ thống tổng hợp dữ liệu hành vi người dùng từ **4 nguồn nhật ký doanh nghiệp**, xây dựng hồ sơ hành vi hợp nhất 8 chiều, sau đó áp dụng mô hình **Isolation Forest** để gắn thẻ các người dùng có hành vi bất thường. Kết quả phân tích được hiển thị trên **Web Dashboard tương tác** với biểu đồ real-time.

---

## ✨ Các tính năng nổi bật

- **Web Dashboard tương tác (Real-time)**: Biểu đồ Plotly.js tương tác (hover, zoom, pan) thay thế hình ảnh tĩnh PNG. Auto-refresh mỗi 30 giây.
- **4 biểu đồ phân tích trực quan**:
  - **PCA Scatter Plot**: Biểu đồ phân cụm 2D hiển thị toàn bộ người dùng, phân biệt bình thường vs bất thường.
  - **Radar Chart**: So sánh profile hành vi Top-5 người dùng nguy cơ cao nhất so với trung bình tổ chức.
  - **Bar Chart**: Xếp hạng điểm bất thường (Anomaly Score) của các ứng viên đe dọa.
  - **Heatmap**: Ma trận tương quan Pearson giữa 8 đặc trưng hành vi.
- **Bảng xếp hạng Insider Threats**: Bảng chi tiết với tô màu mức độ nguy hiểm.
- **Thiết kế OOP hoàn chỉnh**: Lớp `UEBAPipeline` dễ mở rộng và bảo trì.
- **Kỹ nghệ đặc trưng tự động**: Trích xuất tự động các đặc trưng hành vi, tìm kiếm động cột thời gian.
- **Xử lý linh hoạt (Resilience & Fallback)**: Tự động xử lý khi thiếu tệp nhật ký đầu vào.
- **Hỗ trợ 2 chế độ chạy**: CLI (`python src/ueba_pipeline.py`) và Web Dashboard (`python src/web_app.py`).

---

## 🏗️ Kiến trúc Hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                    UEBA Multi-Log Pipeline                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│   │ logon.csv│  │device.csv│  │ email.csv│  │ file.csv │      │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│        │              │              │              │            │
│        ▼              ▼              ▼              ▼            │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  GIAI ĐOẠN 1: Kỹ nghệ đặc trưng (Feature Engineering)│      │
│   │  • Hành vi đăng nhập   • Hành vi sử dụng USB         │      │
│   │  • Hành vi gửi email   • Hành vi truy cập tệp        │      │
│   └──────────────────────┬───────────────────────────────┘      │
│                          │                                      │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  GIAI ĐOẠN 2: Liên kết đa nguồn (Outer Join)         │      │
│   │  Hợp nhất hồ sơ người dùng 8 đặc trưng               │      │
│   └──────────────────────┬───────────────────────────────┘      │
│                          │                                      │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  GIAI ĐOẠN 3: Phát hiện bất thường (Isolation Forest) │      │
│   │  MinMaxScaler → IsolationForest (contamination=5%)    │      │
│   └──────────────────────┬───────────────────────────────┘      │
│                          │                                      │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  GIAI ĐOẠN 4: Giảm chiều & Trực quan hóa (PCA)       │      │
│   │  8D → 2D để hiển thị trên Web Dashboard               │      │
│   └──────────────────────┬───────────────────────────────┘      │
│                          │                                      │
│                          ▼                                      │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  Flask Web Server + Plotly.js Dashboard               │      │
│   │  📍 PCA Scatter   🕸️ Radar Chart                      │      │
│   │  📊 Bar Chart     🔥 Heatmap     🚨 Threats Table    │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8 Đặc trưng hành vi được trích xuất

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

```
ueba-insider-threat/
├── data/                        # Dữ liệu nhật ký (CSV)
│   ├── logon.csv                #   Nhật ký đăng nhập/đăng xuất
│   ├── device.csv               #   Nhật ký thiết bị USB
│   ├── email.csv                #   Nhật ký email
│   └── file.csv                 #   Nhật ký truy cập tệp
├── src/
│   ├── ueba_pipeline.py         # Pipeline ML chính (class UEBAPipeline)
│   ├── web_app.py               # Flask web server phục vụ Dashboard
│   ├── templates/
│   │   └── index.html           # Giao diện Dashboard (Plotly.js)
│   └── static/
│       └── style.css            # CSS Dark Mode theme
├── requirements.txt             # Thư viện Python yêu cầu
└── README.md                    # Hướng dẫn sử dụng
```

---

## 🚀 Hướng dẫn cài đặt & Sử dụng

### 1. Chuẩn bị môi trường
```bash
# Clone dự án
git clone https://github.com/your-username/ueba-insider-threat.git
cd ueba-insider-threat

# Tạo môi trường ảo
python -m venv .venv

# Kích hoạt môi trường ảo
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Cài đặt thư viện
pip install -r requirements.txt
```

### 2. Chuẩn bị dữ liệu
Đặt các tệp CSV vào thư mục `data/`. Hệ thống tối ưu nhất với **CERT Insider Threat Dataset**.

### 3. Chạy Web Dashboard (Khuyến nghị)
```bash
python src/web_app.py
```
Truy cập **http://127.0.0.1:5000** trên trình duyệt để xem Dashboard tương tác.

### 4. Chạy CLI (Chế độ dòng lệnh truyền thống)
```bash
python src/ueba_pipeline.py
```
Kết quả hiển thị trên console + xuất file `ueba_pca_result.png`.

---

## 📊 Hướng dẫn đọc Dashboard

### Thẻ thống kê (Summary Cards)
- **Tổng người dùng**: Số lượng người dùng được hệ thống phân tích.
- **Người dùng bất thường**: Số lượng người bị Isolation Forest gắn cờ cảnh báo.
- **Tỷ lệ bất thường**: Tỷ lệ phần trăm người dùng bất thường trên tổng số.

### Biểu đồ PCA Scatter
- **Điểm xanh lá** 🟢: Người dùng bình thường.
- **Điểm đỏ hình thoi** 🔴: Người dùng bất thường, có nhãn User ID kèm theo.
- Hover vào mỗi điểm để xem chi tiết toàn bộ đặc trưng hành vi.

### Radar Chart
- So sánh profile hành vi của Top-5 người dùng nguy cơ nhất (đường màu) với đường trung bình tổ chức (đường xanh nét đứt).
- Các trục thể hiện tỷ lệ % so với giá trị cao nhất trong toàn bộ dữ liệu.

### Bar Chart
- Hiển thị điểm Anomaly Score. **Điểm càng âm = Người dùng càng bất thường**.
- Màu đỏ: nguy hiểm cao (< -0.3), cam: trung bình (< -0.15), vàng: thấp hơn.

### Heatmap
- Hiển thị mức tương quan (Pearson) giữa các đặc trưng. Giá trị gần 1 (đỏ) = tương quan dương mạnh.

### Bảng Insider Threats
- Xếp hạng chi tiết toàn bộ người dùng bị gắn cờ với đầy đủ số liệu hành vi.
- Giá trị tô đỏ/vàng khi vượt ngưỡng so với toàn bộ người dùng.

---

## 🔬 Chi tiết kỹ thuật

| Mô-đun | Lựa chọn | Lý do |
|---|---|---|
| **Mô hình ML** | Isolation Forest | Phát hiện bất thường không giám sát, hiệu quả cao trên dữ liệu nhiều chiều |
| **Chuẩn hóa** | MinMaxScaler [0,1] | Đảm bảo các đặc trưng có khoảng giá trị khác nhau được so sánh công bằng |
| **Giảm chiều** | PCA (2 Components) | Chiếu 8 chiều xuống 2 chiều để trực quan hóa trên biểu đồ phân tán |
| **Liên kết bảng** | Outer Join | Không bỏ sót người dùng chỉ xuất hiện ở 1 nguồn nhật ký |
| **Web Server** | Flask | Lightweight, tích hợp dễ dàng với Python ML pipeline |
| **Biểu đồ** | Plotly.js | Tương tác (hover, zoom, pan), hỗ trợ real-time update |

---

## 📝 Giấy phép

Dự án được cấp phép theo **Giấy phép MIT**. Xem [LICENSE](LICENSE) để biết chi tiết.
