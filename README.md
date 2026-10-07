# UniFi External Portal (whitelist số điện thoại, không OTP)

Portal thử nghiệm: khách nhập số điện thoại, có trong bảng `customers` và đang active thì
portal gọi API UniFi để cho thiết bị ra internet.

## Chạy thử trên máy
```
pip install -r requirements.txt
cp .env.example .env            # giữ UNIFI_MOCK=1 để thử giả lập
python import_csv.py customers.csv   # CSV có header: phone,name
uvicorn app:app --host 0.0.0.0 --port 8000
```
Mở: http://localhost:8000/guest/s/default/?id=aa:bb:cc:dd:ee:ff&ssid=Test&url=http://example.com

## Deploy trên Render (Web Service, gói Free)
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Environment Variables: xem `.env.example` (đặt `DATABASE_URL` là chuỗi Postgres của Neon)
- Không đưa file `.env` thật lên Git.

## Giao diện
Đặt `static/logo.png` và `static/bg.jpg` (ảnh nền, nên dưới 300KB). Chữ và màu chỉnh bằng biến
`BRAND_TITLE`, `BRAND_SUBTITLE`, `FOOTER_TEXT`, `BRAND_COLOR`.

## Nối UniFi
1. Tạo tài khoản admin cục bộ riêng cho portal, điền vào biến `UNIFI_*`, đặt `UNIFI_MOCK=0`.
2. SSID guest: Hotspot, kiểu External Portal Server, nhập URL portal.
3. Thêm domain và IP của portal vào Pre-Authorization Access.
