"""Nạp danh sách khách vào bảng customers.

Dùng:  python import_csv.py customers.csv
File CSV có header: phone,name   (cột name có thể để trống)
Chạy lại nhiều lần được: số đã có sẽ được cập nhật.
"""
import csv
import sys

from sqlalchemy import text

from app import engine, normalize_phone

SQL = text(
    "INSERT INTO customers (phone, name, active) VALUES (:p, :n, 1) "
    "ON CONFLICT (phone) DO UPDATE SET name = excluded.name, active = 1"
)

ok, bad = 0, []
with open(sys.argv[1], newline="", encoding="utf-8-sig") as f, engine.begin() as c:
    for row in csv.DictReader(f):
        p = normalize_phone(row.get("phone"))
        if not p:
            bad.append(row.get("phone"))
            continue
        c.execute(SQL, {"p": p, "n": (row.get("name") or "").strip()})
        ok += 1

print(f"Đã nạp {ok} số.")
if bad:
    print(f"Bỏ qua {len(bad)} dòng sai định dạng: {bad[:10]}")
