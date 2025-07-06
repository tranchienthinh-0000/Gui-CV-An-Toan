
<h1 align="center">📄 HỆ THỐNG GỬI CV AN TOÀN CÓ KIỂM TRA IP</h1>

<div align="center">
  <p align="center">
    <img src="img/logoDaiNam.png" alt="DaiNam University Logo" width="200"/>
  </p>
</div>

---

# 🔐 Mô tả đề tài

Đây là hệ thống **gửi CV an toàn**, sử dụng kết nối TLS, mã hóa AES-RSA, chữ ký số RSA, và đặc biệt là kiểm tra IP whitelist để đảm bảo rằng **chỉ những địa chỉ IP hợp lệ** mới có thể giao tiếp với server.

---

# 🧠 Chức năng chính

| Tính năng                          | Mô tả                                                                 |
|-----------------------------------|------------------------------------------------------------------------|
| 📤 Gửi CV                          | Người dùng tải lên file `.pdf` và gửi qua kết nối bảo mật TLS         |
| 🔐 Mã hóa & Chữ ký số             | Nội dung file được mã hóa bằng AES-CBC, chữ ký số bằng RSA            |
| 🔏 Kiểm tra toàn vẹn               | Hash SHA-512 kiểm tra tính toàn vẹn dữ liệu                           |
| 🛡️ Kiểm tra IP                    | Server kiểm tra IP gửi đến phải nằm trong danh sách cho phép (`allowed_ips.json`) |
| 🧾 Ghi log truy cập                | Mỗi lượt gửi file được ghi log với IP, thời gian và trạng thái       |
| 📄 Kiểm tra định dạng              | Chỉ cho phép file đúng định dạng `.pdf`                              |
| ✅ Phản hồi kết quả gửi            | Server gửi `ACK` nếu kiểm tra thành công, `NACK` nếu có lỗi           |

---

# 🛠️ Kiến trúc hệ thống

```
Client (Flask app) <----TLS----> Server (Python + SSL socket)
    |                                   |
  Upload PDF                       Kiểm tra IP
  Gửi metadata                     Giải mã AES
  Gửi file mã hóa     <-----→     Xác thực chữ ký số
                                   Kiểm tra hash
                                   Lưu file PDF
```

---

# 🧪 Danh sách IP được phép

```json
// allowed_ips.json
{
  "allowed_ips": [
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8"
  ]
}
```

---

# 🧾 Cấu trúc thư mục

```
📁 project/
│
├── app.py              # Flask App (Client gửi CV)
├── server.py           # TLS Server xử lý và xác thực file
├── allowed_ips.json    # Danh sách IP được phép
├── upload.html         # Giao diện người dùng
├── server.crt / .key   # Chứng chỉ TLS
├── access_log.db       # Log SQLite
└── received_cv_*.pdf   # File đã giải mã và lưu
```

---

# 📦 Cài đặt thư viện cần thiết

```bash
pip install flask pycryptodome PyPDF2
```

---

# 🚀 Cách chạy chương trình

## ▶️ Bước 1: Chạy Server

```bash
python server.py
```

## ▶️ Bước 2: Chạy Client (Flask app)

```bash
python app.py
```

## ▶️ Bước 3: Giao diện gửi CV

<img src="img/giao dien.png" alt="" width="200"/>

---

# 🧪 Các tình huống kiểm thử (Test Case)

| Mã Test | Mô tả kiểm thử                                      | Kết quả mong đợi                |
|---------|------------------------------------------------------|----------------------------------|
| `1`     | Gửi file PDF đúng định dạng từ IP hợp lệ            | Server phản hồi `ACK`           |
| `2a`    | Gửi file không đúng định dạng PDF                   | Server từ chối (`NACK`)         |
| `3a`    | IP nằm ngoài danh sách `allowed_ips.json`           | Kết nối bị từ chối ngay lập tức |
| `3b`    | Giả mạo IP trong metadata không trùng IP thực tế   | Server từ chối xác thực         |

---

# 🔐 Bảo mật sử dụng

| Thành phần       | Công nghệ                | Vai trò                              |
|------------------|--------------------------|---------------------------------------|
| Mã hóa           | AES-CBC (256-bit)        | Mã hóa nội dung file PDF              |
| Chữ ký số        | RSA 2048-bit + SHA-512   | Xác thực và chống giả mạo             |
| TLS              | TLS 1.2 (server.crt)     | Bảo vệ kênh truyền client ↔ server    |
| IP kiểm soát     | `allowed_ips.json`       | Giới hạn truy cập từ IP được phép     |
| Hash             | SHA-512                  | Kiểm tra tính toàn vẹn file           |

---

# 📋 Ghi chú

- Hệ thống **không sử dụng email thực** — đây là mô phỏng quá trình gửi CV an toàn.
- Nếu cần gửi thực qua email, có thể kết hợp thêm SMTP sau bước mã hóa.

---

> ✨ Đây là hệ thống phù hợp cho đồ án môn **An toàn thông tin**, **Mạng máy tính**, hoặc các dự án yêu cầu **bảo mật dữ liệu**.
