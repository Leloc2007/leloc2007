# KidGuard – Tổng quan dự án (v1.2)

## Lịch sử phiên bản

- **1.2** (24/11/2026): (1) Lịch theo từng ngày: `schedule.days` = mảng 7 phần tử `{start,end}`, `days[0]` = Chủ nhật … `days[6]` = Thứ 7; controller tự chuyển lịch cũ (wd/we) sang `days` khi đọc state, vẫn gửi kèm trường cũ cho agent chưa cập nhật. (2) Controller tự cập nhật: đọc `update.json` (version + danh sách tệp + sha256) tại `-UpdateUrl`, mặc định `https://raw.githubusercontent.com/Leloc2007/leloc2007/kidguard` (nhánh `kidguard` của repo Leloc2007/leloc2007); kiểm tra lúc khởi động, mỗi 6 giờ, và khi bấm nút trên dashboard (`POST /api/update-check`); tải xong thì chạy bản mới lồng trong tiến trình cũ. Agent sau khi tự cập nhật cũng chạy bản mới theo cách này. **Ra bản mới:** sửa code, tăng `$Version` ở cả controller.ps1 và agent.ps1, chạy `make-update.py`, đẩy `controller/`, `agent/`, `update.json` lên nhánh `kidguard`.
- **1.1.1** (24/11/2026): Windows Defender trên máy con chặn file uninstall.ps1 (có đoạn gỡ chính sách trình duyệt + sửa hosts) làm setup dừng giữa chừng. Chuyển toàn bộ việc trả lại cài đặt sang `agent.ps1 -Cleanup`; uninstall.ps1 chỉ dừng task, gọi cleanup, xóa thư mục. Setup không dừng nếu không lưu được uninstall.ps1.
- **1.1** (24/11/2026): chống lách (`antiBypass`, mặc định bật): chính sách tắt ẩn danh/khách + chặn tiện ích trên Chrome/Edge/Firefox; agent tự tắt Opera, Brave, Tor, Psiphon, Proton VPN, Windscribe, TunnelBear, Hotspot Shield, Urban VPN, X-VPN, Hola, Betternet, Touch VPN, Cloudflare WARP (theo tên tiến trình hoặc thư mục cài); thêm trang tải các phần mềm này vào hosts; báo `lastBypass` về dashboard. Agent tự cập nhật khi `agentVersion` của controller khác phiên bản đang chạy. Uninstall gỡ thêm các chính sách mới.
- **1.0**: bản đầu tiên.

Phần mềm quản lý laptop Windows của con trong mạng wifi nhà. Viết hoàn toàn bằng PowerShell 5.1 + 1 trang HTML, không cần cài thêm gì.

## Kiến trúc

```
Laptop BỐ MẸ (controller)                     Laptop CỦA CON (agent, chạy quyền SYSTEM)
  controller.ps1  — web server cổng 8765  <──── agent.ps1 check-in mỗi 10 giây
  dashboard.html  — trang quản lý               (báo trạng thái, nhận cài đặt + lệnh)
  data/state.json — mật khẩu, máy, lịch        Áp dụng: Firewall chặn Internet,
                                                 file hosts chặn web, DNS Cloudflare 1.1.1.3,
Điện thoại cùng wifi → http://<IP>:8765          khóa màn hình, nhắn tin, tắt/khởi động lại
```

## Cấu trúc thư mục

| File | Vai trò |
|---|---|
| `Cai-dat-may-bo-me.cmd` | Chuột phải → Run as administrator để cài máy bố mẹ |
| `install-controller.ps1` | Cài controller vào `%LOCALAPPDATA%\KidGuard`, đặt mật khẩu, mở firewall cổng 8765 (chỉ LocalSubnet), tạo Scheduled Task chạy khi đăng nhập, lối tắt Desktop |
| `controller/controller.ps1` | HttpListener: phục vụ dashboard, `/setup`, `/uninstall`, `/agent/*.ps1`, API đăng nhập, API agent (enroll/checkin), API quản lý máy |
| `controller/dashboard.html` | Giao diện quản lý (đăng nhập, thẻ từng máy, lịch, chặn web, lệnh điều khiển, thêm máy bằng mã 6 số) |
| `agent/setup.ps1` | Chạy trên máy con: `irm http://IP:8765/setup \| iex` → nhập mã 6 số, tải agent, phân quyền, tắt DNS-over-HTTPS trên Chrome/Edge/Firefox, tạo 3 task (Agent/Lock/Notify) |
| `agent/agent.ps1` | Vòng lặp 10 giây; giữ cache cài đặt nên vẫn chạy lịch khi máy bố mẹ tắt; có `-DryRun` / `-Once` để thử |
| `agent/notify.ps1` | Hiện hộp thoại "Tin nhắn từ Bố Mẹ" trong phiên của con |
| `agent/uninstall.ps1` | Gỡ task, rule firewall, phần hosts, DNS, policy trình duyệt, thư mục |
| `HUONG-DAN.md` | Hướng dẫn sử dụng cho bố mẹ |

## API controller

- Không cần đăng nhập: `GET /`, `GET /setup`, `GET /uninstall`, `GET /agent/{agent|notify|uninstall}.ps1`, `POST /api/login`
- Agent (header `X-Device-Id` + `X-Device-Key`): `POST /api/agent/enroll` (mã 6 số, hết hạn 30 phút), `POST /api/agent/checkin`
- Bố mẹ (header `X-Auth`, phiên 30 ngày): `GET /api/devices`, `GET /api/info`, `POST /api/enroll-code`, `POST /api/devices/{id}` (name, mode auto/on/off + minutes, schedule, blockedSites, safeDns, antiBypass), `POST /api/devices/{id}/command` (lock, message, shutdown, restart, cancel), `DELETE /api/devices/{id}`

## Mặc định

- Lịch: Thứ 2–Thứ 6 07:00–21:30, Thứ 7 và Chủ nhật 08:00–22:00, bật sẵn, chỉnh được từng ngày
- Lọc web người lớn (Cloudflare for Families) bật sẵn
- Máy được coi là trực tuyến nếu check-in trong 35 giây gần nhất
- Đăng nhập sai 5 lần → khóa 1 phút

## Điều kiện bắt buộc

Tài khoản của con phải là **Standard User**, nếu không con có thể gỡ phần mềm.
