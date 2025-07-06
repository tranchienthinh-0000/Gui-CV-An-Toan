from flask import Flask, request, render_template
import socket
import ssl
import json
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from PyPDF2 import PdfReader
import io

app = Flask(__name__)

# Tạo cặp khóa RSA 2048-bit cho client
client_key = RSA.generate(2048)
client_public_key = client_key.publickey()

# Hàm thêm padding PKCS7
def pad(data):
    padding_len = 16 - (len(data) % 16)
    padding = bytes([padding_len] * padding_len)
    return data + padding

# Hàm mã hóa AES-CBC
def aes_encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data)
    ciphertext = cipher.encrypt(padded_data)
    return iv, ciphertext

# Hàm ký số
def sign_data(data, private_key):
    h = SHA512.new(data)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)

# Hàm kiểm tra định dạng PDF
def is_valid_pdf(data):
    try:
        PdfReader(io.BytesIO(data))
        return True
    except:
        return False

# Hàm gửi CV
def send_cv(host='127.0.0.1', port=12345, file_data=None, filename='cv.pdf', test_case="1"):
    print(f"[Test Case {test_case}]: Starting file upload process")
    if not file_data:
        return False, f"Test Case {test_case}: File rỗng"
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_verify_locations('server.crt')
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    client = context.wrap_socket(client, server_hostname=host)
    
    try:
        client.connect((host, port))
        print(f"[Test Case {test_case}]: Connected to server, TLS version: {client.version()}")
    except Exception as e:
        print(f"[Test Case {test_case}]: Connection error - {e}")
        return False, f"Test Case {test_case}: Lỗi kết nối - {e}"

    # Bước 1: Handshake
    client_ip = "127.0.0.1" if test_case != "3a" else "192.168.1.1"
    print(f"[Test Case {test_case}]: Sending handshake: Hello! {client_ip}")
    client.send(f"Hello! {client_ip}".encode('utf-8'))
    try:
        response = client.recv(1024).decode('utf-8')
        print(f"[Test Case {test_case}]: Received handshake response: {response}")
        if response != "Ready!":
            client.close()
            return False, f"Test Case {test_case}: Handshake thất bại - {response}"
    except Exception as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi nhận phản hồi handshake - {e}"

    # Bước 1.5: Trao đổi khóa công khai
    print(f"[Test Case {test_case}]: Exchanging public keys")
    try:
        client.send(client_public_key.export_key())
        server_pub_key = client.recv(2048)
        server_public_key = RSA.import_key(server_pub_key)
        print(f"[Test Case {test_case}]: Public key exchange successful")
    except Exception as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi trao đổi khóa công khai - {e}"

    # Bước 2: Trao khóa phiên
    print(f"[Test Case {test_case}]: Sending session key and metadata")
    session_key = get_random_bytes(32)
    timestamp = datetime.now().isoformat()
    metadata = f"{filename}|{timestamp}|{client_ip}".encode('utf-8')
    if test_case == "3b":
        metadata = f"{filename}|{timestamp}|tampered_ip".encode('utf-8')
    signature = sign_data(metadata, client_key)

    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    try:
        encrypted_session_key = cipher_rsa.encrypt(session_key)
    except Exception as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi mã hóa khóa phiên - {e}"

    packet = {
        "metadata": base64.b64encode(metadata).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
        "test_case": test_case
    }
    try:
        packet_json = json.dumps(packet)
        if len(packet_json) > 10 * 1024 * 1024:
            return False, f"Test Case {test_case}: Metadata quá lớn"
        print(f"[Test Case {test_case}]: Sending metadata and session key: {packet_json[:100]}...")
        packet_data = packet_json.encode('utf-8')
        client.send(len(packet_data).to_bytes(4, 'big'))
        client.send(packet_data)
    except json.JSONEncodeError as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi mã hóa JSON (Bước 2) - {e}"

    # Bước 3: Gửi file
    print(f"[Test Case {test_case}]: Sending file")
    iv, ciphertext = aes_encrypt(file_data, session_key)
    hash_obj = SHA512.new(iv + ciphertext)
    signature_file = sign_data(iv + ciphertext, client_key)
    try:
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
        sig_b64 = base64.b64encode(signature_file).decode('utf-8')
    except Exception as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi mã hóa Base64 - {e}"
    packet = {
        "iv": iv_b64,
        "cipher": cipher_b64,
        "hash": hash_obj.hexdigest(),
        "sig": sig_b64,
        "test_case": test_case
    }
    try:
        packet_json = json.dumps(packet)
        if len(packet_json) > 10 * 1024 * 1024:
            return False, f"Test Case {test_case}: File dữ liệu quá lớn"
        print(f"[Test Case {test_case}]: Sending encrypted file: {packet_json[:100]}...")
        packet_data = packet_json.encode('utf-8')
        client.send(len(packet_data).to_bytes(4, 'big'))
        client.send(packet_data)
    except json.JSONEncodeError as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi mã hóa JSON (Bước 3) - {e}"

    # Bước 4: Nhận phản hồi
    print(f"[Test Case {test_case}]: Receiving server response")
    try:
        client.settimeout(10.0)
        response = client.recv(1024).decode('utf-8')
        if not response:
            client.close()
            return False, f"Test Case {test_case}: Không nhận được phản hồi từ server"
        elif response == "ACK":
            print(f"[Test Case {test_case}]: File sent successfully! Server response: ACK")
            client.close()
            return True, f"Test Case {test_case}: Gửi CV thành công!"
        else:
            client.close()
            return False, f"Test Case {test_case}: Gửi file thất bại - {response}"
    except socket.timeout:
        client.close()
        return False, f"Test Case {test_case}: Hết thời gian chờ phản hồi từ server"
    except Exception as e:
        client.close()
        return False, f"Test Case {test_case}: Lỗi nhận phản hồi - {e}"

@app.route('/', methods=['GET', 'POST'])
def upload_cv():
    if request.method == 'POST':
        if 'cv' not in request.files:
            return render_template('upload.html', message="Test Case Unknown: Vui lòng chọn file!")
        file = request.files['cv']
        if file.filename == '':
            return render_template('upload.html', message="Test Case Unknown: Vui lòng chọn file!")
        file_data = file.read()
        test_case = request.form.get('test_case', '1')
        if test_case in ["1", "2a", "3b"] and not is_valid_pdf(file_data):
            return render_template('upload.html', message=f"Test Case {test_case}:Không phải file PDF - Yêu cầu chọn đúng file PDF")
        success, message = send_cv(file_data=file_data, filename=file.filename, test_case=test_case)
        return render_template('upload.html', message=message)
    return render_template('upload.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)