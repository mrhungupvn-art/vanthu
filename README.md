# Ứng dụng Văn thư Android

Đây là **client Android** dùng WebView kết nối tới máy chủ Văn thư (`vanthu.py`).

## Không đưa backend vào repository Android

Không đưa các mục sau lên GitHub Android:

- `vanthu.py`
- `data/`
- `data/vanthu.db`
- `data/files/`
- keystore thật

Backend chạy riêng trên máy tính/host.

## Build GitHub Actions

Workflow: `.github/workflows/build-apk.yml`

- JDK 17
- Gradle 8.7
- Android Gradle Plugin 8.5.2
- build debug APK

Sau khi workflow hoàn thành: **Actions → Build APK → Artifacts → vanthu-apk-v1.2**.

## Kết nối máy chủ

Khi app hỏi địa chỉ máy chủ, nhập ví dụ:

`http://192.168.1.10:8080`

Không nhập `localhost:8080` trên điện thoại nếu `vanthu.py` đang chạy trên máy tính.

## Chức năng

- Đăng nhập bằng session cookie `sid`
- WebView JavaScript + DOM Storage
- Chọn file Android để upload
- DownloadManager để tải file về thư mục Downloads
- Gửi cookie phiên khi download
- Hỗ trợ HTTP LAN
