# 🛡️ AI-Driven Enterprise UEBA — Insider Threat Detection System

Hệ thống **User and Entity Behavior Analytics (UEBA)** phát hiện mối đe dọa nội bộ doanh nghiệp bằng Trí tuệ Nhân tạo & Học máy không giám sát, tích hợp giao diện giám sát thời gian thực (Real-time SOC Dashboard).

Hệ thống được thiết kế theo kiến trúc **2 Giai đoạn chuẩn Enterprise (Offline Profiling & Online Detection)** để tối ưu hóa tài nguyên phần cứng, tách biệt quá trình huấn luyện máy học nặng nề và quá trình giám sát trực tuyến tốc độ cao. Đặc biệt, hệ thống đã được nâng cấp với khả năng **thu thập log trực tiếp từ hệ điều hành Windows** theo thời gian thực thay vì giả lập.

---

## 📋 Mục lục
1. [Các tính năng nổi bật](#-các-tính-năng-nổi-bật)
2. [Kiến trúc hệ thống 2 giai đoạn](#-kiến-trúc-hệ-thống-2-giai-đoạn)
3. [Tập dữ liệu phân tách & Cơ chế tối ưu RAM](#-tập-dữ-liệu-phân-tách--cơ-chế-tối-ưu-ram)
4. [Chi tiết 15 đặc trưng hành vi (Feature Engineering)](#-chi-tiết-15-đặc-trưng-hành-vi-feature-engineering)
5. [Thiết kế Cơ sở dữ liệu (Database Schema)](#-thiết-kế-cơ-sở-dữ-liệu-database-schema)
6. [Cấu trúc thư mục dự án](#-cấu-trúc-thư-mục-dự-án)
7. [Hướng dẫn cài đặt chi tiết](#-hướng-dẫn-cài-đặt-chi-tiết)
8. [Hướng dẫn vận hành & Kiểm thử hệ thống](#-hướng-dẫn-vận-hành--kiểm-thử-hệ-thống)
9. [Nguyên lý hoạt động của mã nguồn](#-nguyên-lý-hoạt-động-của-mã-nguồn)
10. [Xử lý sự cố thường gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## ✨ Các tính năng nổi bật

* **Kiến trúc Tách biệt Giai đoạn Huấn luyện & Chạy thực tế**: Mô hình ML được huấn luyện định kỳ offline trên tập dữ liệu tĩnh khổng lồ. Web server khi vận hành hoàn toàn không cần load tập dữ liệu CSV 15GB thô. Khởi động chưa đầy 1 giây và chiếm dụng cực ít RAM.
* **Tích hợp Windows Event Log thật (MỚI)**: Mô đun mới `windows_log_collector.py` sử dụng công cụ `wevtutil` có sẵn trên Windows để tự động lấy các log hệ thống thực tế (Logon/Logoff, cắm/rút thiết bị USB qua PnP, và sự kiện thực thi PowerShell) để phân tích hành vi theo thời gian thực thay vì dùng dữ liệu giả lập.
* **SOC Dashboard thời gian thực**: Tích hợp **WebSockets (Flask-SocketIO)** để truyền phát cảnh báo dị thường xuống trình duyệt ngay lập tức khi phát hiện hành vi tấn công mà không cần tải lại trang.
* **Hỗ trợ Song ngữ Anh/Việt Hoàn chỉnh**: Hệ thống i18n đa ngôn ngữ cho phép chuyển đổi ngôn ngữ giao diện (biểu đồ, bảng sự kiện) nhất quán chỉ với một nút bấm.
* **Hiệu năng Giao diện Tối ưu**: Sử dụng thuật toán so khớp thay đổi file log, kết hợp phương thức `Plotly.react` và tải các API song song để đảm bảo tốc độ phản hồi siêu mượt, loại bỏ độ trễ khi chuyển đổi giữa các tab.
* **Mô hình ML Không giám sát Nâng cao**: Kết hợp thuật toán **Isolation Forest** để đánh giá dị thường đa chiều, kết hợp phương pháp lọc sai lệch phân phối chuẩn **Chebyshev / Sigma (σ)** giúp định lượng mức độ bất thường.
* **Khả năng giải thích cao (Explainability)**: Cung cấp thông tin chi tiết từng đặc trưng bị lệch so với baseline trung bình của chính người dùng đó bao nhiêu Sigma (σ), giúp chuyên viên SOC đưa ra quyết định nhanh chóng.

---

## 🏗️ Kiến trúc hệ thống 2 giai đoạn

Sơ đồ luồng hoạt động tổng thể của hệ thống UEBA:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   GIAI ĐOẠN 1: OFFLINE PROFILING                        │
│                   (Định kỳ chạy offline - ví dụ hằng tuần)               │
│                                                                        │
│  Log lịch sử (CSV / Splits) -> src/offline_profiler.py -> pipeline     │
│    ├── Đọc tuần tự & Phân mảnh (Chunked) các file split lớn             │
│    ├── Xây dựng Master Profile (Tổng hợp hành vi của 1000+ users)       │
│    ├── Huấn luyện mô hình Isolation Forest & MinMaxScaler               │
│    └── Lưu trữ Baselines (Mean, Std) của từng User vào baseline.db      │
│        và xuất mô hình ueba_model.joblib, ueba_scaler.joblib           │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ├──> baseline.db (Hồ sơ hành vi chuẩn)
                                    └──> models/ (Mô hình ML đã train)
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│              GIAI ĐOẠN 2: RUNTIME & REAL-TIME DETECTION                │
│             (Vận hành Web Server & Giám sát 24/7 từ live log)          │
│                                                                        │
│  [Windows Event Collector]                                             │
│  Thu thập log OS thực tế (wevtutil) -> data/r4.2/live_logs/system.log  │
│                                                                        │
│  [Dashboard - web_app.py]              [Engine - online_detector.py]   │
│  Đọc & phân tích live log bằng          Đọc từng dòng log real-time      │
│  live_analyzer.py                      Tính toán trượt, lấy baseline    │
│     ├── Load model & scaler               so sánh Sigma (σ)              │
│     ├── Lấy baseline từ baseline.db       Nếu phát hiện bất thường:       │
│     └── Prediction + PCA + Correlation       Ghi vào alerts.db           │
│                                              Bắn WebSocket lên Web UI    │
│                                                                        │
│  Hiển thị Dashboard UI mượt mà        Cập nhật Real-time Feed & Alert  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Tập dữ liệu phân tách & Cơ chế tối ưu RAM

Do tập dữ liệu log của doanh nghiệp thực tế rất lớn, một số tệp đã được chia nhỏ (split) để lưu trữ hiệu quả trên kho lưu trữ:

1.  **Email log (`email.csv` ~1.3 GB)**: Được chia nhỏ thành 3 phần: `email_1.csv`, `email_2.csv`, `email_3.csv`.
2.  **HTTP log (`http.csv` ~14.5 GB)**: Được chia nhỏ thành 25 phần từ `http_1.csv` tới `http_25.csv`.

### ⚙️ Cơ chế xử lý Chunked trong `ueba_pipeline.py`
Để tránh lỗi **Out-Of-Memory (OOM)** trên các thiết bị kiểm thử thông thường khi nạp cùng lúc hàng chục GB dữ liệu thô:
- Sử dụng hàm `pd.read_csv(..., chunksize=100000)` để đọc tuần tự từng block 100.000 dòng.
- Tự động phát hiện nếu tập dữ liệu chưa được split để xử lý bình thường, đảm bảo tính tương thích.

---

## 📊 Chi tiết 15 đặc trưng hành vi (Feature Engineering)

Hệ thống UEBA liên kết thông tin từ nhiều nguồn nhật ký khác nhau để xây dựng vector đặc trưng (15 chiều) cho mỗi người dùng:

| STT | Tên đặc trưng | Loại đặc trưng | Nguồn (Offline) / Windows Log (Live) | Ý nghĩa bảo mật |
|---|---|---|---|---|
| 1 | `total_logins` | Live (Động) | logon.csv / **System (Event 7001/7002)** | Tổng số lần đăng nhập |
| 2 | `off_hour_logins` | Live (Động) | logon.csv / **System (Event 7001/7002)** | Đăng nhập ngoài giờ (trước 07:00 / sau 18:00) |
| 3 | `total_usb_connects` | Live (Động) | device.csv / **Kernel-PnP (Event 410, 430)** | Tổng số lần kết nối thiết bị USB/Ổ cứng ngoài |
| 4 | `off_hour_usb` | Live (Động) | device.csv / **Kernel-PnP (Event 410, 430)** | Cắm USB ngoài giờ làm việc |
| 5 | `total_emails` | Live (Động) | email_*.csv / *(N/A trên Windows Log)* | Tổng số email đã gửi |
| 6 | `external_emails` | Live (Động) | email_*.csv / *(N/A trên Windows Log)* | Số email gửi ra ngoài tổ chức |
| 7 | `total_file_access` | Live (Động) | file.csv / **PowerShell (40962) / System (7045)** | Thao tác thực thi mã, tạo dịch vụ mới |
| 8 | `exe_zip_downloads` | Live (Động) | file.csv / **PowerShell (40962) / System (7045)** | Thao tác nhạy cảm (tương đương tải exe/zip) |
| 9 | `total_http_requests` | Static (Tĩnh) | http_*.csv / Lấy từ baseline chuẩn | Yêu cầu duyệt web (từ baseline) |
| 10 | `off_hour_http` | Static (Tĩnh) | http_*.csv / Lấy từ baseline chuẩn | Duyệt web ngoài giờ (từ baseline) |
| 11-15 | `o_c_e_a_n_score` | Static (Tĩnh) | psychometric.csv / Baseline | Điểm trắc nghiệm tâm lý Big Five |

> [!NOTE]
> Khi vận hành trực tuyến, hệ thống trích xuất **8 đặc trưng động** trực tiếp từ log thật của hệ điều hành Windows thông qua `windows_log_collector.py`. Đối với email log (do Windows Event Log không hỗ trợ), hệ thống sẽ gán là 0 và chờ nguồn log phụ trợ nếu có.

---

## 💾 Thiết kế Cơ sở dữ liệu (Database Schema)

Hệ thống sử dụng hai cơ sở dữ liệu SQLite:

### 1. Cơ sở dữ liệu Baseline (`baseline.db`)
Lưu trữ hồ sơ hành vi chuẩn của toàn bộ người dùng đã được huấn luyện.
*   **Bảng `baselines`**: Lưu thông số baseline (mean, std) của từng người dùng cụ thể.
*   **Bảng `global_baselines`**: Hồ sơ trung bình của toàn doanh nghiệp (dự phòng).
*   **Bảng `model_meta`**: Metadata của mô hình.

### 2. Cơ sở dữ liệu Cảnh báo (`alerts.db`)
Lưu trữ lịch sử toàn bộ các cảnh báo đã được kích hoạt trực tuyến.
*   **Bảng `alerts`**: Chứa ID, thời gian, user_id, mức độ (CRITICAL/HIGH), điểm số, chi tiết sai lệch (JSON deviations), mô tả sự kiện.

---

## 📂 Cấu trúc thư mục dự án

```text
ueba-insider-threat/
├── data/
│   └── r4.2/
│       ├── alerts.db               # Database SQLite lưu lịch sử cảnh báo real-time
│       ├── baseline.db             # Database SQLite lưu baselines hành vi chuẩn
│       ├── live_logs/
│       │   └── system.log          # File log thời gian thực do Collector đẩy vào
│       └── logon.csv, email_1.csv... # Các log lịch sử tĩnh dùng huấn luyện offline
├── models/
│   ├── ueba_model.joblib           # File model Isolation Forest sau khi huấn luyện xong
│   └── ueba_scaler.joblib          # File MinMaxScaler lưu tỷ lệ chuẩn hóa đặc trưng
├── src/
│   ├── templates/
│   │   └── index.html              # Giao diện SOC Dashboard (HTML, Bootstrap 5, Socket.IO, Plotly)
│   ├── static/
│   │   └── style.css               # CSS styling cho giao diện Dark Mode
│   ├── ueba_pipeline.py            # Khung xử lý ETL, Feature Engineering từ tập dữ liệu CSV (offline)
│   ├── offline_profiler.py         # Huấn luyện mô hình offline, xuất joblib & lưu baseline vào DB
│   ├── live_analyzer.py            # Phân tích system.log live kết hợp DB và model
│   ├── online_detector.py          # Engine giám sát system.log real-time, bắn alert WebSocket
│   ├── windows_log_collector.py    # (MỚI) Thu thập Windows Event Log thật từ hệ điều hành
│   ├── merge_logs.py               # Công cụ gộp log trực tiếp vào log lịch sử (tiện ích)
│   └── web_app.py                  # Flask Web server & Socket.IO hub điều phối
└── requirements.txt                # Danh sách thư viện phụ thuộc
```

---

## 🔍 Chi tiết các nguồn Log & Vị trí lưu trữ

Hệ thống UEBA được thiết kế để hoạt động liên tục bằng cách thu thập, chuẩn hóa và phân tích log từ nhiều nguồn khác nhau. Dưới đây là chi tiết về các nguồn log đầu vào và nơi lưu trữ dữ liệu đầu ra của hệ thống:

### 1. Nguồn thu thập Log (Log Ingestion Sources)
Khi chạy trên Windows, mô-đun `windows_log_collector.py` sử dụng công cụ hệ thống `wevtutil` để truy vấn thời gian thực từ **4 kênh log chính** của hệ điều hành:

| Kênh Event Log (Channel) | Event ID | Loại sự kiện trong UEBA | Mô tả chi tiết hành vi thu thập |
|---|---|---|---|
| **System** | `7001` | `logon` | Người dùng đăng nhập hệ thống thành công (User Logon). |
| **System** | `7002` | `logon` | Người dùng đăng xuất hệ thống (User Logoff) - dùng để theo dõi thời gian hoạt động. |
| **System** | `10000`, `10002` | `device` | Cài đặt / cập nhật driver thiết bị (phát hiện cắm thiết bị lưu trữ ngoài/USB). |
| **System** | `16` | `file` | Truy cập registry hive / thay đổi file cấu hình hệ thống quan trọng. |
| **System** | `7045` | `file` | Khởi tạo hoặc cài đặt một Service mới (hành vi tạo cơ chế chạy ngầm/Persistence). |
| **Kernel-PnP/Configuration** | `410`, `430` | `device` | Kết nối hoặc ngắt kết nối nóng thiết bị phần cứng (USB, ổ cứng di động...). |
| **PowerShell/Operational** | `40961`, `40962`, `4104` | `file` | Khởi chạy PowerShell, tải module, hoặc thực thi khối lệnh PowerShell. |
| **Application** | Level `1`, `2`, `3` | `file` | Lọc các sự kiện ứng dụng ở mức độ nghiêm trọng: Critical (1), Error (2), Warning (3). |

### 2. Vị trí lưu trữ Log & Cơ sở dữ liệu (Log & Database Storage)
Dữ liệu log sau khi thu thập hoặc phân tích sẽ được lưu trữ tại các vị trí sau trong thư mục `data/r4.2/`:

*   **Tệp Log thời gian thực (`data/r4.2/live_logs/system.log`)**:
    *   *Mục đích*: Lưu trữ các sự kiện log thô đã được thu thập và chuẩn hóa sang định dạng JSON Lines của hệ thống UEBA.
    *   *Cơ chế*: Được ghi tự động bởi `windows_log_collector.py` (append liên tục) và được đọc liên tục từ cuối tệp (tailing) bởi `online_detector.py` để phân tích.
    *   *Định dạng ví dụ*:
        ```json
        {"timestamp": "2026-06-26T10:30:15", "user": "admin", "type": "device", "action": "connect", "hour": 10, "device_id": "USB\\VID_0951&PID_1666", "source": "kernel_pnp", "event_id": 410}
        ```
*   **Database Baseline (`data/r4.2/baseline.db`)**:
    *   *Mục đích*: Cơ sở dữ liệu SQLite lưu trữ profile hành vi chuẩn (baseline) của toàn bộ nhân viên trong công ty.
    *   *Nội dung*: Bao gồm các thông số `mean` (trung bình) và `std` (độ lệch chuẩn) của 15 chiều đặc trưng được tính từ dữ liệu lịch sử thông qua `offline_profiler.py`.
*   **Database Cảnh báo (`data/r4.2/alerts.db`)**:
    *   *Mục đích*: Cơ sở dữ liệu SQLite lưu vết toàn bộ các cảnh báo bất thường (Alerts) đã được hệ thống kích hoạt.
    *   *Nội dung*: Lưu thông tin chi tiết về `severity` (CRITICAL / HIGH), điểm số dị thường (`anomaly_score`), và chi tiết các đặc trưng bị lệch baseline (`feature_deviations` dạng JSON).
*   **Thư mục Log lịch sử tĩnh (`data/r4.2/*.csv`)**:
    *   *Mục đích*: Các tệp CSV khổng lồ chứa dữ liệu hoạt động lịch sử (Email, HTTP, Logon, Device, File, Psychometric) dùng để huấn luyện mô hình ML offline ban đầu.

---

## 🚀 Hướng dẫn cài đặt chi tiết

### Yêu cầu hệ thống
*   **Hệ điều hành**: **Windows 10/11** (Bắt buộc nếu muốn chạy live log collector lấy sự kiện Windows), Linux/macOS vẫn chạy được giao diện và dữ liệu tĩnh.
*   **Python**: Phiên bản 3.10 trở lên.
*   **Bộ nhớ RAM**: Tối thiểu 4GB.

### Các bước cài đặt
1.  **Mở Terminal** tại thư mục dự án `UEBA`.
2.  **Khởi tạo môi trường ảo Python (Venv)**:
    ```bash
    python -m venv .venv
    ```
3.  **Kích hoạt môi trường ảo**:
    *   **Windows (PowerShell)**: `.venv\Scripts\activate`
    *   **Windows (CMD)**: `.venv\Scripts\activate.bat`
    *   **Linux / macOS**: `source .venv/bin/activate`
4.  **Cài đặt các thư viện cần thiết**:
    ```bash
    pip install -r requirements.txt
    ```

---

## 🕹️ Hướng dẫn vận hành & Kiểm thử hệ thống

### Bước 1: Huấn luyện mô hình (Offline)
Chạy script huấn luyện để dọn dẹp cơ sở dữ liệu cũ, xử lý các tệp log lịch sử, huấn luyện mô hình Isolation Forest và lưu baseline vào database:
```bash
python src/offline_profiler.py
```
*(Bạn chỉ cần làm bước này một lần, hoặc khi có tệp CSV mới).*

### Bước 2: Khởi chạy Web Dashboard & Hệ thống Giám sát
Chạy ứng dụng chính. Khi Flask khởi chạy, nó sẽ tự động kích hoạt cả **Online Detector** và **Windows Log Collector** dưới dạng background threads:
```bash
python src/web_app.py
```
*   Mở trình duyệt truy cập: **http://127.0.0.1:5000**.
*   Chuyển sang tab **Live Threat Feed**, bạn sẽ thấy mục **Windows Event Log Collector** báo trạng thái `Running` và bộ đếm sự kiện nhảy số (dữ liệu thu trực tiếp từ máy của bạn).

### Bước 3: Kiểm thử luồng thời gian thực
Hệ thống hiện tại đọc **log thật của chính máy tính bạn đang chạy server**. Để kiểm thử chức năng cảnh báo dị thường:
1.  Bật Web Dashboard lên.
2.  Tiến hành **cắm một chiếc USB** vào máy tính.
3.  **Mở PowerShell** lên và gõ vài lệnh.
4.  Đăng xuất và đăng nhập lại Windows.
5.  **Quan sát Dashboard:** Các hành vi trên hệ điều hành sẽ được bắt trực tiếp theo thời gian thực và đẩy ngay lên cảnh báo màn hình nếu nó sai lệch so với Baseline của tổ chức.

---

## 🧠 Nguyên lý hoạt động của mã nguồn

### 1. Mô đun Windows Event Collector (`windows_log_collector.py`)
Mô đun này làm nhiệm vụ thu thập log thực tế thay cho dữ liệu giả lập. Nó gọi tiến trình `wevtutil` của Windows mỗi 3 giây một lần để lấy ra các thay đổi mới nhất từ những channel cấu hình sẵn: `System`, `Microsoft-Windows-Kernel-PnP/Configuration`, và `Microsoft-Windows-PowerShell/Operational`. Log lấy về dạng XML được tự động phân tách (parse) sang định dạng UEBA (JSON) và điền tên tài khoản tương ứng, sau đó xuất ra đuôi `system.log`.

### 2. Bộ Phân tích Live (LiveAnalyzer)
Bộ phân tích `live_analyzer.py` làm nhiệm vụ cầu nối giữa mô hình ML offline và luồng chạy thực tế:
- Khớp `user_id` và truy vấn cơ sở dữ liệu `baseline.db` lấy thông tin tĩnh.
- Chuẩn hóa thông qua `MinMaxScaler` và chuyển tiếp sang mô hình `Isolation Forest`.
- Sử dụng thuật toán PCA chiếu dữ liệu lên không gian 2D phục vụ trực quan hóa bản đồ phân bố.

### 3. Thuật toán phát hiện kết hợp (Hybrid Detection)
Hệ thống sử dụng đồng thời 2 phương pháp:
1.  **Mô hình Học máy (Isolation Forest)**: Tính điểm dị thường đa chiều. Nếu điểm âm và vượt ngưỡng thì cảnh báo.
2.  **Độ lệch Sigma (σ) trên từng đặc trưng**: Đối chiếu giá trị trực tiếp với giá trị trung bình lịch sử:
    $$\text{Deviation} = \frac{|\text{Observed} - \text{Baseline Mean}|}{\text{Baseline Std}}$$
    Nếu có từ **2 đặc trưng** trở lên > 1.0σ hoặc 1 đặc trưng lệch > 3.0σ, hệ thống lập tức gắn cờ cảnh báo (kể cả khi Isolation Forest chưa vượt ngưỡng).

---

## 🛠️ Xử lý sự cố thường gặp (Troubleshooting)

### Lỗi 1: `MinMaxScaler is expecting X features...`
*   **Nguyên nhân:** Mô hình trước đó được huấn luyện với số lượng đặc trưng không khớp.
*   **Cách khắc phục:** Chạy lại lệnh huấn luyện `python src/offline_profiler.py` để đồng bộ lại mô hình.

### Lỗi 2: Tính năng Windows Collector báo lỗi "wevtutil not found"
*   **Nguyên nhân:** Dự án đang chạy trên Linux/macOS. Các tính năng thu thập Event Log chỉ hoạt động trên môi trường hệ điều hành Windows.

### Lỗi 3: UnicodeEncodeError / charmap trên Console
*   **Cách khắc phục:** Chạy lệnh sau trên PowerShell trước khi chạy server:
    ```powershell
    $env:PYTHONIOENCODING="utf-8"
    chcp 65001
    ```
