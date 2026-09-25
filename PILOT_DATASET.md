# PyVul pilot dataset — bản dùng để nhóm review

Đây là bản **pilot đang hoàn thiện**, được đưa lên GitHub để các thành viên trong nhóm kiểm tra dữ liệu, nguồn gốc mẫu và quy trình lọc. Bản này **chưa dùng để công bố accuracy, precision, recall hoặc F1 cuối cùng**. Nhãn và mẫu có thể tiếp tục được sửa sau manual review.

## Dataset chính

- File dùng cho mô hình: `data/model-dataset/all_samples.jsonl`
- Tổng số dòng mẫu: **443**
- Số đơn vị mã nguồn gốc độc lập: **207**
- Trùng lặp đã loại: **3**
- Xung đột nhãn đã loại: **6**
- Mẫu không hợp lệ: **0**

| CWE | Số dòng mẫu |
|---|---:|
| CWE-22 — Path Traversal | 128 |
| CWE-78 — Command Injection | 52 |
| CWE-79 — XSS | 162 |
| CWE-89 — SQL Injection | 46 |
| CWE-287 — Improper Authentication | 49 |
| CWE-798 — Hard-coded Credentials | 6 |

Số liệu trên được lấy từ `data/model-dataset/build_summary.csv` tại thời điểm tạo bản pilot này.

## Cách review

1. Xem mẫu cuối trong `data/model-dataset/all_samples.jsonl`.
2. Xem báo cáo tổng hợp trong `data/model-dataset/build_summary.csv`.
3. Xem các mẫu trùng/xung đột đã bị loại trong `duplicates.jsonl` và `label_conflicts.jsonl` cùng thư mục.
4. Truy ngược từng batch tại `data/supplement/<cwe>/batches/<batch>/`:
   - `candidates.jsonl`: mẫu được trích xuất ban đầu;
   - `extraction_review.jsonl`: thông tin phục vụ kiểm tra việc trích xuất;
   - `processed/accepted.jsonl`: mẫu đã qua bộ lọc và được chấp nhận;
   - `processed/rejected.jsonl`: mẫu bị loại cùng lý do;
   - `processed/manual_review.jsonl`: mẫu cần con người xem lại.

## Quy ước khi góp ý

Khi báo một mẫu có vấn đề, nên ghi kèm: `sample_id`, CWE, batch/CVE, file và hàm, nhãn hiện tại, nhãn đề xuất, lý do và bằng chứng từ bản vá. Không sửa trực tiếp dữ liệu tổng hợp nếu chưa cập nhật dữ liệu nguồn của batch; sau đó cần chạy lại pipeline để tạo `all_samples.jsonl` nhất quán.

## Kiểm tra kỹ thuật

Sau khi tạo môi trường Python, cài phụ thuộc bằng `pip install -r requirements-dev.txt` và chạy `python -m pytest -q`. Test kiểm tra pipeline và cấu trúc xử lý; kết quả test đạt không đồng nghĩa nhãn bảo mật đã chính xác tuyệt đối, nên manual review vẫn là bước bắt buộc.

## Phạm vi bản chia sẻ

Repository không chứa `.venv`, cache hay thư mục `outputs/` vì đây là dữ liệu cục bộ và kết quả mô hình dung lượng lớn. Các file `merge-preview` của từng batch cũng được bỏ qua vì chúng chỉ lặp lại toàn bộ dataset; bản tổng hợp chính vẫn nằm trong `data/model-dataset/`.

Một số export tham chiếu rất rộng của PyVul gốc và các dòng đã bị loại cũng chỉ được giữ trên máy phát triển, không đưa vào bản pilot. Chúng không phải đầu vào trực tiếp để thành viên review 443 dòng mẫu đã tổng hợp và có thể chứa chuỗi credential minh họa từ các security advisory công khai.
