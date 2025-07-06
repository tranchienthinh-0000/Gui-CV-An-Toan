import socket
import ssl
import json
import base64
import sqlite3
import ipaddress
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from PyPDF2 import PdfReader
import io
import os

# Tạo cặp khóa RSA 2048-bit cho server
server_key = RSA.generate(2048)
server_public_key = server_key.publickey()

# Đọc danh sách IP hợp lệ từ file JSON
def load_allowed_ips():
    try:
        with open('allowed_ips.json', 'r') as f:
            data = json.load(f)
            print(f"[Server] Danh sách IP được phép: {data['allowed_ips']}")
            return data['allowed_ips']
    except Exception as e:
        print(f"[Server] Lỗi đọc allowed_ips.json: {e}")
        return ["127.0.0.1"]

ALLOWED_IPS = load_allowed_ips()

# Kiểm tra xem IP có hợp lệ không
def is_ip_allowed(client_ip, allowed_ips):
    try:
        client_ip_addr = ipaddress.ip_address(client_ip)
        for ip_entry in allowed_ips:
            if '/' in ip_entry:
                network = ipaddress.ip_network(ip_entry, strict=False)
                if client_ip_addr in network:
                    return True
            elif ip_entry == client_ip:
                return True
        return False
    except Exception as e:
        print(f"[Server] Lỗi kiểm tra IP: {e}")
        return False

# Ghi log truy cập vào SQLite
def log_ip(ip, test_case, status):
    try:
        conn = sqlite3.connect('access_log.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS logs (ip TEXT, timestamp TEXT, test_case TEXT, status TEXT)')
        c.execute('INSERT INTO logs VALUES (?, ?, ?, ?)', (ip, datetime.now().isoformat(), test_case, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Test Case {test_case}]: Lỗi ghi log SQLite: {e}")

# Hàm bỏ padding PKCS7
def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

# Hàm giải mã AES-CBC
def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext)

# Hàm xác minh chữ ký
def verify_signature(data, signature, public_key):
    h = SHA512.new(data)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except:
        return False

# Hàm kiểm tra định dạng PDF
def is_valid_pdf(data):
    try:
        pdf = PdfReader(io.BytesIO(data))
        return True
    except:
        return False

# Xử lý client
def handle_client(client_socket, client_address):
    test_case = "Unknown"
    try:
        client_ip = client_address[0]
        print(f"\n[Test Case {test_case}]: Kết nối từ {client_ip}, Phiên bản TLS: {client_socket.version()}")
        log_ip(client_ip, test_case, "Connected")

        # Bước 1: Handshake
        print(f"[Test Case {test_case}]: Bước 1: Handshake")
        client_socket.settimeout(10.0)
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            print(f"[Test Case {test_case}]: Không nhận được dữ liệu handshake")
            client_socket.send("NACK - Không nhận được dữ liệu handshake".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: No handshake data")
            client_socket.close()
            return
        print(f"[Test Case {test_case}]: Nhận thông điệp handshake: {data}")
        if not data.startswith("Hello!"):
            print(f"[Test Case {test_case}]: Handshake không hợp lệ")
            client_socket.send("NACK - Invalid handshake".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: Invalid handshake")
            client_socket.close()
            return
        received_ip = data.split(" ")[1]
        if not is_ip_allowed(client_ip, ALLOWED_IPS):
            print(f"[Test Case {test_case}]: IP không hợp lệ: {client_ip}")
            client_socket.send(f"NACK - IP không hợp lệ: {client_ip}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: Invalid IP {client_ip}")
            client_socket.close()
            return
        print(f"[Test Case {test_case}]: IP hợp lệ, gửi Ready!")
        client_socket.send("Ready!".encode('utf-8'))
        log_ip(client_ip, test_case, "Handshake successful")

        # Bước 1.5: Trao đổi khóa công khai
        print(f"[Test Case {test_case}]: Bước 1.5: Trao đổi khóa công khai")
        try:
            client_pub_key = client_socket.recv(2048)
            client_public_key = RSA.import_key(client_pub_key)
            client_socket.send(server_public_key.export_key())
            print(f"[Test Case {test_case}]: Trao đổi khóa công khai thành công")
        except Exception as e:
            print(f"[Test Case {test_case}]: Lỗi trao đổi khóa công khai: {e}")
            client_socket.send(f"NACK - Lỗi trao đổi khóa công khai: {str(e)}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: Key exchange error {str(e)}")
            client_socket.close()
            return

        # Bước 2: Nhận metadata và khóa phiên
        print(f"[Test Case {test_case}]: Bước 2: Nhận metadata và khóa")
        size_data = client_socket.recv(4)
        if not size_data:
            print(f"[Test Case {test_case}]: Không nhận được kích thước metadata")
            client_socket.send("NACK - Không nhận được kích thước metadata".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: No metadata size")
            client_socket.close()
            return
        size = int.from_bytes(size_data, 'big')
        data = b""
        received_size = 0
        max_size = 10 * 1024 * 1024
        while received_size < size:
            part = client_socket.recv(min(8192, size - received_size))
            if not part:
                print(f"[Test Case {test_case}]: Dữ liệu metadata không đầy đủ")
                client_socket.send("NACK - Dữ liệu metadata không đầy đủ".encode('utf-8'))
                log_ip(client_ip, test_case, "Failed: Incomplete metadata")
                client_socket.close()
                return
            data += part
            received_size += len(part)
            if received_size > max_size:
                print(f"[Test Case {test_case}]: Dữ liệu metadata quá lớn")
                client_socket.send("NACK - Dữ liệu metadata quá lớn".encode('utf-8'))
                log_ip(client_ip, test_case, "Failed: Metadata too large")
                client_socket.close()
                return
        try:
            packet = json.loads(data.decode('utf-8'))
            test_case = packet.get("test_case", "Unknown")
            print(f"[Test Case {test_case}]: Nhận metadata, chữ ký, khóa phiên: {str(packet)[:100]}...")
        except json.JSONDecodeError as e:
            print(f"[Test Case {test_case}]: Lỗi JSON (Bước 2): {e}")
            client_socket.send(f"NACK - JSON không hợp lệ: {str(e)}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: JSON error {str(e)}")
            client_socket.close()
            return

        metadata = base64.b64decode(packet["metadata"])
        signature = base64.b64decode(packet["signature"])
        encrypted_session_key = base64.b64decode(packet["session_key"])

        if not verify_signature(metadata, signature, client_public_key) or client_ip != metadata.decode('utf-8').split("|")[2]:
            print(f"[Test Case {test_case}]: Lỗi xác thực hoặc IP không khớp")
            client_socket.send(f"NACK - Xác thực metadata thất bại hoặc IP không khớp: {client_ip}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: Metadata verification or IP mismatch")
            client_socket.close()
            return

        cipher_rsa = PKCS1_OAEP.new(server_key)
        try:
            session_key = cipher_rsa.decrypt(encrypted_session_key)
        except Exception as e:
            print(f"[Test Case {test_case}]: Lỗi giải mã khóa phiên: {e}")
            client_socket.send(f"NACK - Lỗi giải mã khóa phiên: {str(e)}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: Session key decryption error {str(e)}")
            client_socket.close()
            return

        # Bước 3: Nhận và kiểm tra file
        print(f"[Test Case {test_case}]: Bước 3: Nhận và kiểm tra file")
        size_data = client_socket.recv(4)
        if not size_data:
            print(f"[Test Case {test_case}]: Không nhận được kích thước file")
            client_socket.send("NACK - Không nhận được kích thước file".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: No file size")
            client_socket.close()
            return
        size = int.from_bytes(size_data, 'big')
        data = b""
        received_size = 0
        while received_size < size:
            part = client_socket.recv(min(8192, size - received_size))
            if not part:
                print(f"[Test Case {test_case}]: Dữ liệu file không đầy đủ")
                client_socket.send("NACK - Dữ liệu file không đầy đủ".encode('utf-8'))
                log_ip(client_ip, test_case, "Failed: Incomplete file data")
                client_socket.close()
                return
            data += part
            received_size += len(part)
            if received_size > max_size:
                print(f"[Test Case {test_case}]: Dữ liệu file quá lớn")
                client_socket.send("NACK - Dữ liệu file quá lớn".encode('utf-8'))
                log_ip(client_ip, test_case, "Failed: File too large")
                client_socket.close()
                return
        try:
            packet = json.loads(data.decode('utf-8'))
            print(f"[Test Case {test_case}]: Nhận file mã hóa, hash, IV, chữ ký: {str(packet)[:100]}...")
        except json.JSONDecodeError as e:
            print(f"[Test Case {test_case}]: Lỗi JSON (Bước 3): {e}")
            client_socket.send(f"NACK - JSON file không hợp lệ: {str(e)}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: JSON file error {str(e)}")
            client_socket.close()
            return

        iv = base64.b64decode(packet["iv"])
        ciphertext = base64.b64decode(packet.get("cipher", ""))
        received_hash = packet["hash"]
        signature = base64.b64decode(packet["sig"])

        if not verify_signature(iv + ciphertext, signature, client_public_key):
            print(f"[Test Case {test_case}]: Lỗi xác minh chữ ký file")
            client_socket.send("NACK - Chữ ký file không hợp lệ".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: Invalid file signature")
            client_socket.close()
            return

        computed_hash = SHA512.new(iv + ciphertext).hexdigest()
        if computed_hash != received_hash:
            print(f"[Test Case {test_case}]: Lỗi tính toàn vẹn: nhận {received_hash[:16]}..., tính {computed_hash[:16]}...")
            client_socket.send(f"NACK - Hash không khớp".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: Hash mismatch")
            client_socket.close()
            return

        plaintext = aes_decrypt(ciphertext, session_key, iv)
        if not is_valid_pdf(plaintext):
            print(f"[Test Case {test_case}]: File không phải PDF")
            client_socket.send("NACK - File không phải PDF".encode('utf-8'))
            log_ip(client_ip, test_case, "Failed: Invalid PDF")
            client_socket.close()
            return
        
        # Lưu file với tên duy nhất
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"received_cv_{timestamp}_{os.urandom(4).hex()}.pdf"
        with open(filename, "wb") as f:
            f.write(plaintext)
        with open("debug_decrypted.pdf", "wb") as debug_f:
            debug_f.write(plaintext)

        # Bước 4: Gửi phản hồi
        print(f"[Test Case {test_case}]: Bước 4: Gửi phản hồi")
        print(f"[Test Case {test_case}]: Tất cả kiểm tra hợp lệ, gửi ACK")
        client_socket.send("ACK".encode('utf-8'))
        log_ip(client_ip, test_case, "Success: File received")
    except Exception as e:
        print(f"[Test Case {test_case}]: Lỗi server: {e}")
        try:
            client_socket.send(f"NACK - Lỗi server: {str(e)}".encode('utf-8'))
            log_ip(client_ip, test_case, f"Failed: Server error {str(e)}")
        except:
            print(f"[Test Case {test_case}]: Không thể gửi NACK, client đã ngắt kết nối")
    finally:
        client_socket.close()

# Chạy server với TLS
def start_server(host='127.0.0.1', port=12345):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    server = context.wrap_socket(server, server_side=True)
    server.bind((host, port))
    server.listen(5)
    print(f"[Server] Server TLS đang chạy trên {host}:{port}, Phiên bản TLS: {context.protocol}")
    while True:
        try:
            client_socket, client_address = server.accept()
            print(f"[Server] Kết nối từ {client_address}, Phiên bản TLS: {client_socket.version()}")
            handle_client(client_socket, client_address)
        except Exception as e:
            print(f"[Server] Lỗi chấp nhận kết nối: {e}")

if __name__ == "__main__":
    start_server()