# KidGuard – Quản lý laptop của con trong mạng nhà

Trang web quản lý chạy trên **laptop của bố mẹ**. Bố mẹ mở trang này bằng máy tính hoặc **điện thoại cùng wifi** để:

- **Tắt / bật Internet** từng máy, ngay lập tức hoặc trong 15 phút, 30 phút, 1 giờ, 2 giờ
- **Lịch dùng mạng**: mỗi ngày trong tuần (Thứ 2 đến Chủ nhật) có khung giờ riêng, ngoài giờ máy tự chặn
- **Chặn trang web**: TikTok, Facebook, YouTube, Roblox, game web… hoặc tự nhập tên trang
- **Lọc web người lớn và web độc hại** tự động (Cloudflare for Families)
- **Khóa màn hình, gửi tin nhắn, tắt máy, khởi động lại** máy của con
- **Chống lách** (mới ở bản 1.1, bật sẵn): tắt tab ẩn danh và chế độ khách trên Chrome / Edge / Firefox, chặn cài tiện ích trình duyệt, tự tắt Opera, Brave, Tor và các phần mềm VPN, chặn trang tải các phần mềm đó. Khi con thử dùng, trang quản lý hiện cảnh báo màu vàng.

Khi chặn Internet, máy của con vẫn vào được mạng nội bộ nên vẫn nhận được lệnh. Nếu máy bố mẹ tắt, máy con **vẫn giữ lịch và cài đặt cuối cùng**.

---

## Cập nhật

Từ bản **1.2**, KidGuard **tự cập nhật**: máy bố mẹ tự kiểm tra bản mới trên mạng mỗi 6 giờ (và mỗi lần bật máy), tự tải về rồi tự chạy lại; máy của con tự cập nhật theo sau vài giây. Cuối trang quản lý có dòng ghi phiên bản đang dùng và nút **Kiểm tra cập nhật** nếu muốn cập nhật ngay.

Nếu đang dùng bản cũ hơn 1.2 thì phải cài tay **một lần cuối**:

1. **Máy bố mẹ:** giải nén thư mục `KidGuard` mới, chuột phải `Cai-dat-may-bo-me.cmd` → **Run as administrator**. Khi được hỏi *"Đặt mật khẩu mới?"* gõ **k** để giữ mật khẩu cũ.
2. **Máy của con:** nếu đang ở bản 1.1 trở lên thì tự cập nhật. Nếu còn ở bản 1.0 (hoặc chưa cài) thì chạy lệnh cài như Bước 2 bên dưới.

---

## Bước 1 – Cài trên laptop của bố mẹ (làm 1 lần)

1. Chép cả thư mục `KidGuard` vào laptop của bố mẹ.
2. Chuột phải file **`Cai-dat-may-bo-me.cmd`** → **Run as administrator**.
3. Đặt mật khẩu cho trang quản lý. **Đừng cho con biết mật khẩu này.**
4. Trang quản lý sẽ tự mở. Trên Desktop có thêm lối tắt **"Quan ly may cua con"**.
   - Trên điện thoại: mở `http://<IP-máy-bố-mẹ>:8765`. Địa chỉ cụ thể hiện ở cuối màn hình cài đặt.

## Bước 2 – Cài trên mỗi laptop của con

1. Trên trang quản lý, bấm **"+ Thêm máy của con"** để nhận **mã 6 số** và **lệnh cài đặt**.
2. Trên laptop của con, đăng nhập bằng **tài khoản Admin của bố mẹ**.
3. Chuột phải nút Start → **Terminal (Admin)**, dán lệnh dạng sau rồi Enter:
   ```
   irm http://192.168.1.7:8765/setup | iex
   ```
4. Nhập mã 6 số. Máy của con sẽ hiện trên trang quản lý sau vài giây.

## ⚠️ Bắt buộc: tài khoản của con phải là **Standard**

Nếu con có quyền Admin, con có thể gỡ phần mềm. Cách đổi:
*Settings → Accounts → Other users → chọn tài khoản của con → Change account type → **Standard User***.

---

## Gỡ cài đặt

- **Máy của con:** mở PowerShell (Admin) và chạy
  `powershell -ExecutionPolicy Bypass -File "C:\ProgramData\KidGuard\uninstall.ps1"`
  Lệnh này gỡ phần mềm và mở lại toàn bộ Internet.
- **Máy bố mẹ:** mở Task Scheduler, xóa thư mục `KidGuard`, rồi xóa thư mục `%LOCALAPPDATA%\KidGuard`.

## Lưu ý

- **Máy bố mẹ phải đang bật** thì mới gửi lệnh được. Lịch dùng mạng vẫn chạy trên máy con kể cả khi máy bố mẹ tắt.
- Nếu IP máy bố mẹ thay đổi, máy con sẽ tự tìm lại bằng **tên máy**. Để chắc chắn hơn, nên **cố định IP** cho máy bố mẹ trong modem Viettel (mục *DHCP → Static IP / IP Reservation*).
- Danh sách chặn web có hiệu quả tốt trên trình duyệt, nhưng một số ứng dụng hoặc game cài sẵn trên máy dùng nhiều tên miền khác nhau nên có thể không chặn hết. Khi đó dùng **Tắt mạng** hoặc **Lịch dùng mạng**.
- Nhật ký của máy con nằm ở `C:\ProgramData\KidGuard\agent.log`.
- **Chống lách** chặn tất cả tiện ích trình duyệt (vì nhiều tiện ích là VPN). Nếu con cần một tiện ích cho việc học, tắt ô *Chống lách* trong mục *Chặn trang web* của máy đó. Chrome, Edge, Firefox, Cốc Cốc vẫn dùng bình thường.
- Phần mềm VPN rất nhiều, KidGuard chỉ nhận ra những loại phổ biến. Cách chắc chắn nhất vẫn là **Tắt mạng** / **Lịch dùng mạng**: dù dùng VPN nào cũng không vào được Internet.
