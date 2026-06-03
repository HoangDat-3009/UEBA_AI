# 🛡️ AI-Driven Enterprise UEBA — Insider Threat Detection System

Hệ thống **User and Entity Behavior Analytics (UEBA)** phát hiện mối đe dọa nội bộ doanh nghiệp bằng Trí tuệ Nhân tạo & Học máy không giám sát, tích hợp giám sát thời gian thực (Real-time SOC Dashboard).

Hệ thống được thiết kế theo kiến trúc **2 Giai đoạn chuẩn Enterprise (Offline Profiling & Online Detection)** để tối ưu hóa tài nguyên phần cứng, hỗ trợ xử lý luồng dữ liệu cực lớn trong môi trường thực tế doanh nghiệp.

---

## 📋 Mục lục
1. [Các tính năng nổi bật](#-các-tính-năng-nổi-bật)
2. [Kiến trúc hệ thống 2 giai đoạn](#-kiến-trúc-hệ-thống-2-giai-đoạn)
3. [Chi tiết 14-16 đặc trưng hành vi (Feature Engineering)](#-chi-tiết-14-16-đặc-trưng-hành-vi-feature-engineering)
4. [Thiết kế Cơ sở dữ liệu (Database Schema)](#-thiết-kế-cơ-sở-dữ-liệu-database-schema)
5. [Cấu trúc thư mục dự án](#-cấu-trúc-thư-mục-dự-án)
6. [Hướng dẫn cài đặt chi tiết](#-hướng-dẫn-cài-đặt-chi-tiết)
7. [Hướng dẫn vận hành & Kiểm thử hệ thống](#-hướng-dẫn-vận-hành--kiểm-thử-hệ-thống)
8. [Nguyên lý hoạt động của mã nguồn](#-nguyên-lý-hoạt-động-của-mã-nguồn)
9. [Xử lý sự cố thường gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## ✨ Các tính năng nổi bật

* **Kiến trúc Tách biệt 2 Giai đoạn**: Đảm bảo hiệu năng cao. Việc huấn luyện mô hình ML nặng nề được thực hiện định kỳ offline, luồng kiểm tra trực tuyến chỉ chạy so khớp toán học cực nhanh.
* **SOC Dashboard thời gian thực**: Sử dụng **WebSockets (Flask-SocketIO)** để truyền phát cảnh báo dị thường xuống trình duyệt ngay lập tức mà không cần tải lại trang.
* **Mô hình ML nâng cao**: Kết hợp thuật toán **Isolation Forest (Huấn luyện không giám sát)** và phương pháp lọc sai lệch phân phối chuẩn **Chebyshev / Sigma (σ)** để phát hiện dị thường hành vi.
* **Bộ Giả lập Log thông minh (Log Simulator)**: Tự động tải thông tin người dùng từ cơ sở dữ liệu và liên tục tạo ra các hoạt động mô phỏng (Logon, USB, File, Email), đồng thời tự động tiêm (inject) các hành vi tấn công (ví dụ: cắm USB ngoài giờ, tải lượng lớn tệp zip nhạy cảm lúc nửa đêm).
* **Khả năng giải thích cao (Explainability)**: Cung cấp thông tin chi tiết từng đặc trưng bị lệch so với baseline trung bình của chính người dùng đó bao nhiêu Sigma (σ).

---

## 🏗️ Kiến trúc hệ thống 2 giai đoạn

Sơ đồ hoạt động chi tiết của hệ thống:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   GIAI ĐOẠN 1: OFFLINE PROFILING                        │
│                   (Định kỳ chạy offline - ví dụ hằng tuần)               │
│                                                                        │
│  Log lịch sử (CSV) -> src/offline_profiler.py -> ueba_pipeline.py      │
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
│                   GIAI ĐOẠN 2: ONLINE DETECTION                        │
│                   (Giám sát thời gian thực 24/7)                       │
│                                                                        │
│  Log mới phát sinh -> data/r4.2/live_logs/system.log                   │
│    ├── online_detector.py đọc dòng log mới theo thời gian thực         │
│    ├── Cập nhật trạng thái trượt (Sliding state) của user hiện tại     │
│    ├── Ghép với Baseline tĩnh (điểm tâm lý, role...) từ baseline.db    │
│    ├── MinMaxScaler chuẩn hóa và Isolation Forest chấm điểm dị thường  │
│    └── Đối chiếu sai lệch Sigma (σ) của user so với baseline chuẩn    │
│                                    │
│                        (Nếu vượt ngưỡng dị thường)                     │
│                                    │
│  Tạo Cảnh báo -> Ghi vào alerts.db -> Bắn WebSocket -> Web UI          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Chi tiết 14-16 đặc trưng hành vi (Feature Engineering)

Hệ thống UEBA liên kết thông tin từ 5 nguồn nhật ký tĩnh/động khác nhau để xây dựng vector đặc trưng cho mỗi người dùng:

| STT | Tên đặc trưng | Nguồn nhật ký | Ý nghĩa bảo mật |
|---|---|---|---|
| 1 | `total_logins` | logon.csv | Tổng số lần đăng nhập |
| 2 | `off_hour_logins` | logon.csv | Số lần đăng nhập ngoài giờ làm việc (trước 07:00 / sau 18:00) |
| 3 | `total_usb_connects`| device.csv| Tổng số lần cắm USB |
| 4 | `off_hour_usb` | device.csv| Số lần cắm USB ngoài giờ làm việc (nguy cơ đánh cắp dữ liệu) |
| 5 | `total_emails` | email.csv | Tổng số email đã gửi |
| 6 | `external_emails` | email.csv | Số email gửi ra ngoài tổ chức hoặc chứa tệp đính kèm |
| 7 | `total_file_access` | file.csv  | Tổng số lần truy cập tệp tin trên máy trạm |
| 8 | `exe_zip_downloads` | file.csv  | Số lần thao tác trên tệp nguy hiểm `.exe` / `.zip` |
| 9 | `o_score` | psychometric.csv | Điểm cởi mở (Openness) — Chỉ số tâm lý tính cách |
| 10| `c_score` | psychometric.csv | Điểm tận tụy (Conscientiousness) |
| 11| `e_score` | psychometric.csv | Điểm hướng ngoại (Extraversion) |
| 12| `a_score` | psychometric.csv | Điểm dễ chịu (Agreeableness) |
| 13| `n_score` | psychometric.csv | Điểm bất ổn cảm xúc (Neuroticism) |
| 14| `role_changes` | LDAP / Active Directory | Số lần thay đổi vị trí/quyền hạn (role) trong lịch sử |
| 15| `total_http_requests`| http.csv (Tùy chọn) | Tổng số yêu cầu HTTP duyệt web |
| 16| `off_hour_http` | http.csv (Tùy chọn) | Hoạt động duyệt web ngoài giờ làm việc |

*Lưu ý: Nếu một tệp nhật ký bị thiếu (ví dụ: `http.csv` bị xóa), hệ thống sẽ tự động loại bỏ các đặc trưng liên quan khỏi vector huấn luyện (vector co giãn còn 14 đặc trưng). Cơ chế Online Detector sẽ tự động phát hiện số lượng đặc trưng này từ DB.*

---

## 💾 Thiết kế Cơ sở dữ liệu (Database Schema)

Hệ thống sử dụng hai cơ sở dữ liệu SQLite trong thư mục `data/r4.2/` để đảm bảo tính gọn nhẹ và tốc độ đọc/ghi cao:

### 1. Cơ sở dữ liệu Baseline (`baseline.db`)
Lưu trữ hồ sơ hành vi chuẩn của toàn bộ người dùng đã được huấn luyện.

*   **Bảng `baselines`**: Lưu thông số baseline của từng người dùng cụ thể.
    *   `user_id` (TEXT, PK): Mã định danh người dùng (ví dụ: `NGF0157`).
    *   `feature_name` (TEXT, PK): Tên đặc trưng hành vi.
    *   `mean` (REAL): Giá trị trung bình lịch sử của người dùng này.
    *   `std` (REAL): Độ lệch chuẩn hành vi của người dùng này (được cấu hình bằng $5\%$ độ lệch chuẩn toàn cục để phản ánh chính xác biến động cá nhân).
    *   `min_val` / `max_val` / `p95` (REAL): Các thống kê phân phối khác.
    *   `computed_at` (TIMESTAMP): Thời gian tính toán.
*   **Bảng `global_baselines`**: Hồ sơ trung bình của toàn doanh nghiệp (sử dụng làm baseline dự phòng khi gặp người dùng mới chưa có lịch sử).
    *   `feature_name` (TEXT, PK), `mean`, `std`, `min_val`, `max_val`, `p95`, `computed_at`.
*   **Bảng `model_meta`**: Metadata của mô hình.
    *   `key` (TEXT, PK), `value` (TEXT), `updated_at` (TIMESTAMP).

### 2. Cơ sở dữ liệu Cảnh báo (`alerts.db`)
Lưu trữ lịch sử toàn bộ các cảnh báo đã được kích hoạt.

*   **Bảng `alerts`**:
    *   `id` (INTEGER, PK AUTOINCREMENT): Mã cảnh báo.
    *   `timestamp` (TIMESTAMP): Thời điểm phát hiện dị thường.
    *   `user_id` (TEXT): Mã người dùng bị gắn cờ.
    *   `severity` (TEXT): Mức độ nghiêm trọng (`CRITICAL` nếu score < -0.2, ngược lại là `HIGH`).
    *   `anomaly_score` (REAL): Điểm dị thường từ mô hình Isolation Forest (càng âm càng nguy hiểm).
    *   `feature_deviations` (TEXT - JSON): Mô tả chi tiết các đặc trưng bị lệch chuẩn (ví dụ ghi nhận, giá trị trung bình, mức độ lệch Sigma).
    *   `description` (TEXT): Mô tả lỗi bằng tiếng Việt.
    *   `acknowledged` (INTEGER): Trạng thái xác nhận của phân tích viên SOC (`0` hoặc `1`).

---

## 📂 Cấu trúc thư mục dự án

```text
ueba-insider-threat/
├── data/
│   └── r4.2/
│       ├── LDAP/                   # Chứa log lịch sử Active Directory quản lý role
│       ├── alerts.db               # Database lưu lịch sử cảnh báo real-time
│       ├── baseline.db             # Database lưu baselines hành vi chuẩn
│       ├── live_logs/
│       │   └── system.log          # File ghi log thời gian thực để online_detector đọc
│       ├── logon.csv, file.csv...  # Các log lịch sử tĩnh dùng huấn luyện offline
│       └── psychometric.csv        # Log đo trắc nghiệm tâm lý người dùng
├── models/
│   ├── ueba_model.joblib           # File model Isolation Forest sau khi train
│   └── ueba_scaler.joblib          # File MinMaxScaler lưu tỷ lệ chuẩn hóa đặc trưng
├── src/
│   ├── templates/
│   │   └── index.html              # Frontend giao diện SOC Dashboard
│   ├── static/
│   │   └── style.css               # CSS styling cho giao diện Dark Mode
│   ├── ueba_pipeline.py            # Logic cốt lõi xử lý feature engineering & train ML
│   ├── offline_profiler.py         # Giai đoạn 1: Huấn luyện offline & tính baseline
│   ├── online_detector.py          # Giai đoạn 2: Giám sát log, tính toán độ lệch & cảnh báo
│   ├── log_simulator.py            # Trình giả lập sinh log trực tiếp & tiêm mã độc
│   ├── merge_logs.py               # Công cụ gộp log trực tiếp vào log lịch sử định kỳ
│   └── web_app.py                  # Flask server và SocketIO phát cảnh báo
└── requirements.txt                # Danh sách thư viện phụ thuộc
```

---

## 🚀 Hướng dẫn cài đặt chi tiết

### Yêu cầu hệ thống
*   **Hệ điều hành**: Windows 10/11, Linux hoặc macOS.
*   **Python**: Phiên bản 3.10 trở lên.

### Các bước cài đặt
1.  **Mở Terminal** tại thư mục dự án `ueba-insider-threat`.
2.  **Khởi tạo môi trường ảo Python (Venv)**:
    ```bash
    python -m venv .venv
    ```
3.  **Kích hoạt môi trường ảo**:
    *   **Windows (PowerShell)**:
        ```powershell
        .venv\Scripts\activate
        ```
    *   **Windows (CMD)**:
        ```cmd
        .venv\Scripts\activate.bat
        ```
    *   **Linux / macOS**:
        ```bash
        source .venv/bin/activate
        ```
4.  **Cài đặt các thư viện cần thiết**:
    ```bash
    pip install -r requirements.txt
    ```

---

## 🕹️ Hướng dẫn vận hành & Kiểm thử hệ thống

Hãy tuân thủ đúng trình tự 3 bước sau để chạy hệ thống demo:

### Bước 1: Huấn luyện mô hình và thiết lập Baselines (Offline)
Chạy script này để hệ thống dọn dẹp cơ sở dữ liệu cũ, đọc toàn bộ log lịch sử trong `data/r4.2/`, huấn luyện mô hình Isolation Forest và lưu baseline của 1000 người dùng vào database:
```bash
python src/offline_profiler.py
```
*Đầu ra mong đợi:*
*   Huấn luyện thành công mô hình với 14 đặc trưng hành vi.
*   Tạo thành công file mô hình trong thư mục `models/`.
*   Xuất hiện thông báo: `Offline Profiling completed. Baselines saved for 1000 users.`

### Bước 2: Khởi chạy Web Dashboard & Engine giám sát trực tuyến
Khởi chạy Flask Web Server. Tiến trình này sẽ tự động chạy một luồng nền (background thread) khởi tạo `OnlineDetector` để liên tục theo dõi tệp `data/r4.2/live_logs/system.log`.
```bash
python src/web_app.py
```
*Đầu ra mong đợi:*
*   Server khởi chạy tại địa chỉ: **http://127.0.0.1:5000**.
*   Mở trình duyệt truy cập địa chỉ trên. Tab **Live Threat Feed** hiển thị trạng thái `Kết nối (Online)`.

### Bước 3: Khởi chạy Trình giả lập Log & Tiêm mã độc (Simulator)
Mở một cửa sổ Terminal mới (nhớ kích hoạt lại `.venv`), chạy script giả lập để liên tục đẩy dòng log mới vào hệ thống:
```bash
python src/log_simulator.py
```
*Đầu ra mô phỏng:*
*   Mỗi 2 giây, simulator sẽ sinh các log hoạt động bình thường cho 20 user được lấy ngẫu nhiên từ database.
*   Ngẫu nhiên (xác suất 2% mỗi giây), simulator sẽ cảnh báo: `[WARNING] Injecting anomaly for AAE0190` và ghi dồn dập hàng loạt hành vi bất thường (60-100 lượt tải file zip và 30-50 email ngoài giờ lúc 3 giờ sáng).
*   **Kiểm tra Web Dashboard:** Bạn sẽ thấy các dòng log thời gian thực nhảy lên lập tức trên tab **Live Threat Feed** cùng biểu đồ lịch sử nhảy số mà không cần tải lại trang!

### Bước 4: Tích hợp định kỳ (Tùy chọn)
Khi chạy thực tế lâu ngày, tệp log trực tiếp `system.log` sẽ phình to. Phân tích viên có thể chạy công cụ gộp log trực tiếp vào dữ liệu tĩnh để chuẩn bị cho lượt train tiếp theo:
```bash
python src/merge_logs.py
```
Script này sẽ chuyển đổi định dạng và tích lũy dữ liệu trực tiếp vào các file `.csv` của tập dữ liệu `r4.2`, sau đó dọn trống file `system.log` về 0 byte để tránh đọc lặp lại.

---

## 🧠 Nguyên lý hoạt động của mã nguồn

### 1. Đồng bộ hóa Feature động (`online_detector.py`)
Mã nguồn phát hiện dị thường trực tuyến sử dụng giải pháp tải đặc trưng linh hoạt:
```python
# Tự động lọc ra danh sách các đặc trưng được huấn luyện thực tế
all_possible_features = [
    "total_logins", "off_hour_logins", "total_usb_connects", "off_hour_usb",
    "total_emails", "external_emails", "total_file_access", "exe_zip_downloads",
    "total_http_requests", "off_hour_http", "o_score", "c_score", "e_score", 
    "a_score", "n_score", "role_changes"
]
self.feature_names = [f for f in all_possible_features if f in self.global_baselines]
```
Khi tiến hành đánh giá dị thường cho một sự kiện log trực tiếp của người dùng, detector sẽ xây dựng vector input cho scaler bằng cách kết hợp số lượng đếm tích lũy thực tế của 8 đặc trưng động và lấy thông tin baseline tĩnh (`mean`) của chính user đó từ cơ sở dữ liệu đối với các đặc trưng còn lại.

### 2. Thuật toán phát hiện 2 lớp kết hợp
Hệ thống sử dụng đồng thời 2 phương pháp kích hoạt cảnh báo:
1.  **Mô hình Học máy (Isolation Forest)**:
    Sử dụng mô hình đa chiều đã được chuẩn hóa để tính toán điểm dị thường toàn cục. Nếu điểm bất thường (Anomaly Score) âm và vượt ngưỡng nhạy cảm, cảnh báo sẽ được kích hoạt.
2.  **Độ lệch phân phối chuẩn Chebyshev/Sigma (σ) trên từng đặc trưng**:
    Đối chiếu giá trị ghi nhận trực tiếp của người dùng với giá trị trung bình lịch sử của họ:
    $$\text{Deviation} = \frac{|\text{Observed} - \text{Baseline Mean}|}{\text{Baseline Std}}$$
    Nếu có từ **2 đặc trưng** trở lên vượt quá độ lệch chuẩn cho phép (> 1.0σ), hệ thống sẽ lập tức gắn cờ cảnh báo kể cả khi mô hình Isolation Forest chưa phản hồi kịp thời.

---

## 🛠️ Xử lý sự cố thường gặp (Troubleshooting)

### Lỗi 1: `MinMaxScaler is expecting 14 features as input`
*   **Nguyên nhân:** Mô hình trước đó được huấn luyện trên một số lượng cột đặc trưng khác với danh sách đặc trưng được định cấu hình trong Online Detector (thường xảy ra khi bạn xóa/thêm một file log tĩnh như `http.csv` mà chưa dọn dẹp database cũ).
*   **Cách khắc phục:** Chạy lại lệnh huấn luyện `python src/offline_profiler.py`. Phiên bản mới đã tích hợp sẵn cơ chế dọn dẹp database cũ trước khi chạy profiling, đảm bảo đồng bộ 100%.

### Lỗi 2: Console bị lỗi `UnicodeEncodeError / charmap` khi chạy trên Windows
*   **Nguyên nhân:** Terminal Windows sử dụng bảng mã mặc định không hỗ trợ tiếng Việt có dấu khi các script Python in thông báo ra màn hình.
*   **Cách khắc phục:** Chạy lệnh sau trên terminal của Windows trước khi chạy các script Python để chuyển mã hóa Terminal sang UTF-8:
    ```powershell
    $env:PYTHONIOENCODING="utf-8"
    chcp 65001
    ```
    *Lưu ý: Hệ thống cũng đã được tích hợp cơ chế dự phòng tự động chuyển mã UTF-8 sang ASCII thay thế khi ghi nhận lỗi in ra màn hình.*
