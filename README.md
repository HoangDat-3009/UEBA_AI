# 🛡️ AI-Driven Enterprise UEBA — Insider Threat Detection System

Hệ thống **User and Entity Behavior Analytics (UEBA)** phát hiện mối đe dọa nội bộ doanh nghiệp bằng Trí tuệ Nhân tạo & Học máy không giám sát, tích hợp giao diện giám sát thời gian thực (Real-time SOC Dashboard).

Hệ thống được thiết kế theo kiến trúc **2 Giai đoạn chuẩn Enterprise (Offline Profiling & Online Detection)** để tối ưu hóa tài nguyên phần cứng, tách biệt quá trình huấn luyện máy học nặng nề và quá trình giám sát trực tuyến tốc độ cao, hỗ trợ xử lý luồng dữ liệu cực lớn bằng cơ chế đọc phân đoạn (chunked streaming).

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

* **Kiến trúc Tách biệt Giai đoạn Huấn luyện & Chạy thực tế (MỚI)**: Mô hình ML được huấn luyện định kỳ offline trên tập dữ liệu tĩnh khổng lồ. Web server khi vận hành hoàn toàn không cần load tập dữ liệu CSV 15GB thô. Thay vào đó, bộ phân tích `live_analyzer.py` sẽ nạp mô hình đã train, kết hợp log thực tế (`system.log`) và hồ sơ baseline lưu trong cơ sở dữ liệu `baseline.db` để phát hiện dị thường tức thời. Máy chủ khởi động trong chưa đầy 1 giây và chiếm dụng cực ít RAM.
* **SOC Dashboard thời gian thực**: Tích hợp **WebSockets (Flask-SocketIO)** để truyền phát cảnh báo dị thường xuống trình duyệt ngay lập tức khi phát hiện hành vi tấn công mà không cần tải lại trang.
* **Hỗ trợ Song ngữ Anh/Việt Hoàn chỉnh (MỚI)**: Hệ thống i18n đa ngôn ngữ cho phép chuyển đổi ngôn ngữ giao diện (bao gồm các biểu đồ, tham số đặc trưng và bảng sự kiện) một cách nhất quán và trực quan chỉ với một nút bấm.
* **Hiệu năng Giao diện Tối ưu (MỚI)**: Sử dụng thuật toán so khớp thay đổi file log (hashing size + mtime) để tránh xử lý trùng lặp. Đồng thời, áp dụng phương thức `Plotly.react` giúp cập nhật biểu đồ phân tích (PCA, Feature Correlation, Feature Averages) siêu mượt, loại bỏ hiện tượng lag UI của trình duyệt.
* **Mô hình ML Không giám sát Nâng cao**: Kết hợp thuật toán **Isolation Forest** để đánh giá dị thường đa chiều toàn cục, kết hợp phương pháp lọc sai lệch phân phối chuẩn **Chebyshev / Sigma (σ)** giúp định lượng cụ thể mức độ bất thường.
* **Bộ Giả lập Log thông minh (Log Simulator)**: Tự động tạo ra các hoạt động mô phỏng (Logon, USB, File, Email), đồng thời tự động tiêm (inject) các hành vi tấn công (ví dụ: cắm USB ngoài giờ, tải lượng lớn tệp zip/exe nhạy cảm lúc nửa đêm) để kiểm thử SOC Dashboard.
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
│  Log mới phát sinh -> data/r4.2/live_logs/system.log                   │
│                                                                        │
│  [Dashboard - web_app.py]              [Engine - online_detector.py]   │
│  Đọc & phân tích live log bằng          Đọc từng dòng log real-time      │
│  live_analyzer.py                      Tính toán trượt, lấy baseline    │
│     ├── Load model & scaler               so sánh Sigma (σ)              │
│     ├── Đọc system.log tĩnh hiện tại      Nếu phát hiện bất thường:       │
│     ├── Lấy baseline từ baseline.db          Ghi vào alerts.db           │
│     └── Prediction + PCA + Correlation       Bắn WebSocket lên Web UI    │
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
- Sử dụng hàm `pd.read_csv(..., chunksize=100000)` để đọc tuần tự từng block 100.000 dòng từ các file split.
- Áp dụng cấu trúc dữ liệu Dictionary tích lũy để tính toán các chỉ số thống kê tổng hợp hành vi của người dùng trực tiếp trên từng chunk mà không cần giữ toàn bộ bản ghi log trong RAM.
- Tự động phát hiện nếu tập dữ liệu chưa được split (vẫn tồn tại tệp đơn lẻ `email.csv` hoặc `http.csv`) để xử lý bình thường, đảm bảo tính tương thích ngược.

---

## 📊 Chi tiết 15 đặc trưng hành vi (Feature Engineering)

Hệ thống UEBA liên kết thông tin từ nhiều nguồn nhật ký khác nhau để xây dựng vector đặc trưng (15 chiều) cho mỗi người dùng:

| STT | Tên đặc trưng | Loại đặc trưng | Nguồn nhật ký (Offline) / Cách lấy (Live) | Ý nghĩa bảo mật |
|---|---|---|---|---|
| 1 | `total_logins` | Live (Động) | logon.csv / Phân tích `system.log` | Tổng số lần đăng nhập của người dùng |
| 2 | `off_hour_logins` | Live (Động) | logon.csv / Phân tích `system.log` | Đăng nhập ngoài giờ làm việc (trước 07:00 / sau 18:00) |
| 3 | `total_usb_connects` | Live (Động) | device.csv / Phân tích `system.log` | Tổng số lần kết nối thiết bị USB |
| 4 | `off_hour_usb` | Live (Động) | device.csv / Phân tích `system.log` | Số lần cắm USB ngoài giờ làm việc |
| 5 | `total_emails` | Live (Động) | email_*.csv / Phân tích `system.log` | Tổng số email đã gửi |
| 6 | `external_emails` | Live (Động) | email_*.csv / Phân tích `system.log` | Số email gửi ra ngoài tổ chức |
| 7 | `total_file_access` | Live (Động) | file.csv / Phân tích `system.log` | Tổng số lần truy cập tệp tin trên máy trạm |
| 8 | `exe_zip_downloads` | Live (Động) | file.csv / Phân tích `system.log` | Thao tác trên tệp tin đuôi nhạy cảm `.exe` / `.zip` |
| 9 | `total_http_requests` | Static (Tĩnh) | http_*.csv / Lấy từ baseline chuẩn | Tổng số yêu cầu duyệt web HTTP (lấy từ baseline) |
| 10 | `off_hour_http` | Static (Tĩnh) | http_*.csv / Lấy từ baseline chuẩn | Yêu cầu duyệt web ngoài giờ làm việc (lấy từ baseline) |
| 11 | `o_score` | Static (Tĩnh) | psychometric.csv / Lấy từ baseline chuẩn | Điểm cởi mở (Openness) — Trắc nghiệm tâm lý |
| 12 | `c_score` | Static (Tĩnh) | psychometric.csv / Lấy từ baseline chuẩn | Điểm tận tụy (Conscientiousness) — Trắc nghiệm tâm lý |
| 13 | `e_score` | Static (Tĩnh) | psychometric.csv / Lấy từ baseline chuẩn | Điểm hướng ngoại (Extraversion) — Trắc nghiệm tâm lý |
| 14 | `a_score` | Static (Tĩnh) | psychometric.csv / Lấy từ baseline chuẩn | Điểm dễ chịu (Agreeableness) — Trắc nghiệm tâm lý |
| 15 | `n_score` | Static (Tĩnh) | psychometric.csv / Lấy từ baseline chuẩn | Điểm bất ổn cảm xúc (Neuroticism) — Trắc nghiệm tâm lý |

> [!NOTE]
> Khi vận hành trực tuyến, hệ thống trích xuất **8 đặc trưng động** trực tiếp từ tệp log thực tế (`system.log`). Còn **7 đặc trưng tĩnh** (liên quan đến duyệt web và bài kiểm tra tâm lý Big Five) sẽ được tự động truy vấn từ cơ sở dữ liệu `baseline.db` dựa trên `user_id` để điền vào vector đầu vào cho mô hình Isolation Forest, giúp giảm độ trễ và khối lượng tính toán trực tuyến.

---

## 💾 Thiết kế Cơ sở dữ liệu (Database Schema)

Hệ thống sử dụng hai cơ sở dữ liệu SQLite trong thư mục `data/r4.2/` để đảm bảo tính gọn nhẹ và tốc độ đọc/ghi cao:

### 1. Cơ sở dữ liệu Baseline (`baseline.db`)
Lưu trữ hồ sơ hành vi chuẩn của toàn bộ người dùng đã được huấn luyện.

*   **Bảng `baselines`**: Lưu thông số baseline của từng người dùng cụ thể.
    *   `user_id` (TEXT, PK): Mã định danh người dùng (ví dụ: `AJF0370`).
    *   `feature_name` (TEXT, PK): Tên đặc trưng hành vi.
    *   `mean` (REAL): Giá trị trung bình lịch sử.
    *   `std` (REAL): Độ lệch chuẩn hành vi (độ biến động cá nhân).
    *   `min_val` / `max_val` / `p95` (REAL): Các thống kê phân phối khác.
    *   `computed_at` (TIMESTAMP): Thời gian tính toán.
*   **Bảng `global_baselines`**: Hồ sơ trung bình của toàn doanh nghiệp (sử dụng làm baseline dự phòng khi gặp người dùng mới chưa có lịch sử).
*   **Bảng `model_meta`**: Metadata của mô hình.

### 2. Cơ sở dữ liệu Cảnh báo (`alerts.db`)
Lưu trữ lịch sử toàn bộ các cảnh báo đã được kích hoạt trực tuyến.

*   **Bảng `alerts`**:
    *   `id` (INTEGER, PK AUTOINCREMENT): Mã cảnh báo.
    *   `timestamp` (TIMESTAMP): Thời điểm phát hiện dị thường.
    *   `user_id` (TEXT): Mã người dùng bị gắn cờ.
    *   `severity` (TEXT): Mức độ nghiêm trọng (`CRITICAL` hoặc `HIGH`).
    *   `anomaly_score` (REAL): Điểm dị thường từ mô hình Isolation Forest (càng âm càng nguy hiểm).
    *   `feature_deviations` (TEXT - JSON): Mô tả chi tiết các đặc trưng bị lệch chuẩn và độ lệch Sigma tương ứng.
    *   `description` (TEXT): Mô tả chi tiết hành vi bằng tiếng Anh hoặc tiếng Việt.
    *   `acknowledged` (INTEGER): Trạng thái xác nhận của phân tích viên SOC (`0` hoặc `1`).

---

## 📂 Cấu trúc thư mục dự án

```text
ueba-insider-threat/
├── data/
│   └── r4.2/
│       ├── LDAP/                   # Chứa log lịch sử LDAP để tính toán thay đổi vai trò
│       ├── alerts.db               # Database SQLite lưu lịch sử cảnh báo real-time
│       ├── baseline.db             # Database SQLite lưu baselines hành vi chuẩn của người dùng
│       ├── live_logs/
│       │   └── system.log          # File log thời gian thực (JSON Lines) dạng hoạt động mô phỏng
│       ├── logon.csv, file.csv...  # Các log lịch sử tĩnh dùng huấn luyện offline
│       ├── email_1.csv...          # File split của email.csv
│       ├── http_1.csv...           # File split của http.csv
│       └── psychometric.csv        # Kết quả trắc nghiệm tâm lý của 1000 người dùng
├── models/
│   ├── ueba_model.joblib           # File model Isolation Forest sau khi huấn luyện xong
│   └── ueba_scaler.joblib          # File MinMaxScaler lưu tỷ lệ chuẩn hóa đặc trưng
├── src/
│   ├── templates/
│   │   └── index.html              # Giao diện SOC Dashboard (HTML, Bootstrap 5, Socket.IO, Plotly)
│   ├── static/
│   │   └── style.css               # CSS styling cho giao diện Dark Mode / Glassmorphism
│   ├── ueba_pipeline.py            # Khung xử lý ETL, Feature Engineering từ tập dữ liệu CSV (offline)
│   ├── offline_profiler.py         # Huấn luyện mô hình offline, xuất joblib & lưu baseline vào DB
│   ├── live_analyzer.py            # Phân tích system.log live, kết hợp DB và model để tính toán dashboard
│   ├── online_detector.py          # Engine giám sát system.log real-time, bắn alert WebSocket
│   ├── log_simulator.py            # Trình giả lập sinh log và tiêm (inject) mã độc
│   ├── merge_logs.py               # Công cụ gộp log trực tiếp vào log lịch sử (tiện ích)
│   └── web_app.py                  # Flask Web server & Socket.IO hub điều phối
└── requirements.txt                # Danh sách thư viện phụ thuộc
```

---

## 🚀 Hướng dẫn cài đặt chi tiết

### Yêu cầu hệ thống
*   **Hệ điều hành**: Windows 10/11, Linux hoặc macOS.
*   **Python**: Phiên bản 3.10 trở lên.
*   **Bộ nhớ RAM**: Tối thiểu 4GB (nhờ cơ chế chunked processing, không yêu cầu RAM khủng).

### Các bước cài đặt
1.  **Mở Terminal** tại thư mục dự án `UEBA`.
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

Hãy tuân thủ đúng trình tự các bước sau để chạy hệ thống:

### Bước 1: Huấn luyện mô hình và thiết lập Baselines (Offline)
Chạy script huấn luyện để dọn dẹp cơ sở dữ liệu cũ, xử lý song song các tệp split và file đơn lẻ trong `data/r4.2/`, tiến hành trích xuất đặc trưng tuần tự, huấn luyện mô hình Isolation Forest và lưu baseline của người dùng vào database:
```bash
python src/offline_profiler.py
```
*Đầu ra mong đợi:*
*   Xử lý thành công các file phân đoạn của `email` và `http` mà không gặp lỗi tràn bộ nhớ.
*   Tạo thành công file mô hình trong thư mục `models/`.
*   Xuất hiện thông báo: `Offline Profiling completed. Baselines saved for 1000 users.`

### Bước 2: Khởi chạy Web Dashboard & Engine giám sát trực tuyến
Khởi chạy Flask Web Server. Tiến trình này sẽ tự động khởi chạy ngầm `OnlineDetector` (sử dụng một background thread) để liên tục theo dõi tệp `data/r4.2/live_logs/system.log`.
```bash
python src/web_app.py
```
*Đầu ra mong đợi:*
*   Server khởi chạy thành công tại địa chỉ: **http://127.0.0.1:5000**.
*   Mở trình duyệt truy cập địa chỉ trên. Tab **Live Threat Feed** hiển thị trạng thái `Connected / Kết nối`. Giao diện SOC Dashboard tải tức thì không giật lag.

### Bước 3: Khởi chạy Trình giả lập Log & Tiêm mã độc (Simulator)
Mở một cửa sổ Terminal mới (nhớ kích hoạt lại `.venv`), chạy script giả lập để liên tục đẩy dòng log mới vào hệ thống:
```bash
python src/log_simulator.py
```
*Đầu ra mô phỏng:*
*   Mỗi 2 giây, simulator sinh log hoạt động bình thường cho các user.
*   Thỉnh thoảng simulator sẽ tự động tiêm hành vi tấn công (ví dụ: cắm USB ngoài giờ, tải lượng lớn tệp zip nhạy cảm lúc nửa đêm).
*   **Kiểm tra Web Dashboard:** Các dòng log và biểu đồ nhảy lên lập tức trên tab **Live Threat Feed** cùng biểu đồ mà không cần tải lại trang. Các cảnh báo bất thường hiển thị trực quan dạng thông báo nổi (toast notifications).

---

## 🧠 Nguyên lý hoạt động của mã nguồn

### 1. Cơ chế Đọc theo block (Chunked Processing)
Trong `ueba_pipeline.py`, thay vì load toàn bộ file csv vào memory:
```python
reader = pd.read_csv(file_path, chunksize=100_000, low_memory=False)
for chunk in reader:
    # Trích xuất đặc trưng & cộng dồn vào dictionary
```
Phương pháp này giúp khống chế lượng RAM sử dụng tối đa chỉ khoảng vài trăm MB ngay cả khi xử lý file `http.csv` nặng gần 15 GB.

### 2. Bộ Phân tích Live (LiveAnalyzer)
Bộ phân tích trực tuyến `live_analyzer.py` làm nhiệm vụ cầu nối giữa mô hình ML offline và luồng chạy thực tế:
- Quét nhanh file log `system.log`.
- Tổng hợp các chỉ số hoạt động động của người dùng (Logon, USB, File, Email).
- Khớp `user_id` và truy vấn cơ sở dữ liệu `baseline.db` lấy thông tin tĩnh của người dùng để hoàn thiện vector đặc trưng 15 chiều.
- Chuẩn hóa thông qua `MinMaxScaler` và chuyển tiếp sang mô hình `Isolation Forest` để chấm điểm dị thường.
- Dùng thuật toán PCA chiếu dữ liệu lên không gian 2 chiều phục vụ trực quan hóa bản đồ phân bố hành vi.

### 3. Thuật toán phát hiện kết hợp (Hybrid Detection)
Hệ thống sử dụng đồng thời 2 phương pháp kích hoạt cảnh báo:
1.  **Mô hình Học máy (Isolation Forest)**: Sử dụng mô hình đa chiều đã được chuẩn hóa để tính toán điểm dị thường toàn cục. Nếu điểm bất thường (Anomaly Score) âm và vượt ngưỡng nhạy cảm, cảnh báo sẽ được kích hoạt.
2.  **Độ lệch phân phối chuẩn Chebyshev/Sigma (σ) trên từng đặc trưng**: Đối chiếu giá trị ghi nhận trực tiếp của người dùng với giá trị trung bình lịch sử của họ:
    $$\text{Deviation} = \frac{|\text{Observed} - \text{Baseline Mean}|}{\text{Baseline Std}}$$
    Nếu có từ **2 đặc trưng** trở lên vượt quá độ lệch chuẩn cho phép (> 1.0σ) hoặc có đặc trưng lệch cực độ (> 3.0σ), hệ thống sẽ lập tức gắn cờ cảnh báo kể cả khi điểm Isolation Forest chưa vượt ngưỡng.

---

## 🛠️ Xử lý sự cố thường gặp (Troubleshooting)

### Lỗi 1: `MinMaxScaler is expecting 15 features as input` hoặc tương tự
*   **Nguyên nhân:** Mô hình trước đó được huấn luyện trên một số lượng cột đặc trưng khác với cấu hình chạy thực tế hiện tại.
*   **Cách khắc phục:** Chạy lại lệnh huấn luyện `python src/offline_profiler.py` để đồng bộ lại mô hình và database baseline mới nhất.

### Lỗi 2: Console bị lỗi `UnicodeEncodeError / charmap` trên Windows
*   **Nguyên nhân:** Terminal mặc định của Windows không hiển thị tốt các bảng mã ký tự Unicode / tiếng Việt có dấu.
*   **Cách khắc phục:** Chạy lệnh sau trên terminal của Windows trước khi chạy các script Python để chuyển mã hóa Terminal sang UTF-8:
    ```powershell
    $env:PYTHONIOENCODING="utf-8"
    chcp 65001
    ```
