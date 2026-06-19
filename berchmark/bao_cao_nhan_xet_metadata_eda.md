# Báo Cáo Nhận Xét Metadata EDA

## 1. Tổng quan dữ liệu

Tập metadata hiện có tổng cộng **10,470 GitHub repositories**. Nhìn chung, các trường định danh và điều kiện nền có độ đầy đủ tốt. Các trường như `full_name`, `html_url`, `stargazers_count`, `forks_count`, `size`, `created_at`, `updated_at`, `pushed_at` đều có mặt đầy đủ trong dữ liệu.

Về điều kiện nền, toàn bộ repo trong tập hiện tại đều là repo public, không bị archived, không bị disabled và không phải fork. Trường `language` gần như toàn bộ là Python, với **10,462 repo**, chiếm khoảng **99.92%**.

Điều này cho thấy tập metadata nhìn chung phù hợp với mục tiêu ban đầu: thu thập candidate project Python public, còn hoạt động và có tín hiệu cộng đồng.

Hình tổng quan dưới đây cho thấy `stars`, `forks` và `size` đều có phân phối lệch phải mạnh. Một số repo rất lớn kéo trục x dài ra, làm phần lớn repo bị dồn về phía trái nếu vẽ trên full range.

![Tổng quan phân phối stars, forks và size](eda_report_images/eda_chart_cell_12_2.png)

## 2. Mức độ thiếu metadata

Một số trường metadata vẫn có tình trạng thiếu thông tin:

| Trường        | Số lượng thiếu | Tỷ lệ |
| --------------- | -----------------: | ------: |
| `topics`      |              3,514 |  33.56% |
| `homepage`    |              5,103 |  48.74% |
| `license`     |              1,101 |  10.52% |
| `description` |                491 |   4.69% |
| `language`    |                  8 |   0.08% |

Trường thiếu nhiều nhất là `topics`, với **3,514 repo**, tương đương **33.56%**. Tuy nhiên, `topics` là trường optional trên GitHub, nên việc thiếu topic không nhất thiết đồng nghĩa với repo kém chất lượng.

Trường `homepage` cũng thiếu nhiều, với **5,103 repo**, tương đương **48.74%**. Đây cũng là trường optional, nên chỉ nên xem như tín hiệu phụ.

Hai trường cần chú ý hơn là `description` và `license`. `description` thiếu **491 repo** (**4.69%**), còn `license` thiếu **1,101 repo** (**10.52%**). Repo thiếu license có thể gây khó khăn nếu cần tái sử dụng, chia sẻ hoặc công bố benchmark về sau.

## 3. Ngôn ngữ trong description

Trong trường `description`, có **1,661 repo** chứa ký tự non-ASCII, chiếm khoảng **15.86%**. Ngoài ra, có khoảng **750 repo** có description có khả năng không phải tiếng Anh theo heuristic dựa trên tỷ lệ ký tự non-ASCII, chiếm khoảng **7.16%**.

Cần lưu ý đây chỉ là ước lượng nhanh, chưa phải language detection chính xác. Nhóm này nên được kiểm tra thêm nếu benchmark yêu cầu repo có mô tả tiếng Anh rõ ràng.

## 4. Phân phối stars

Phân phối stars cho thấy phần lớn repo nằm trong nhóm phổ biến vừa phải. Có **8,046 repo** nằm trong khoảng **50-2,000 stars**, chiếm khoảng **76.85%**.

![Repo count by stars bucket](eda_report_images/eda_chart_cell_13_3.png)

Theo biểu đồ bucket, stars tập trung chủ yếu ở các khoảng:

- 100-199 stars
- 200-499 stars
- 500-999 stars
- 1k-2k stars

Trong đó, nhóm **200-499 stars** là một trong các vùng có số lượng repo cao nhất. Điều này cho thấy crawler không chỉ thu thập các repo cực lớn, mà còn bao phủ nhiều project có mức độ phổ biến trung bình. Đây là đặc điểm phù hợp cho việc tạo pool benchmark rộng, tránh việc chỉ tập trung vào một vài repo nổi tiếng.

## 5. Phân phối forks

Phân phối forks cũng cho thấy phần lớn repo nằm trong vùng thấp đến trung bình. Có **9,613 repo** nằm trong khoảng **50-1,000 forks**, chiếm khoảng **91.81%**.

![Repo count by forks bucket](eda_report_images/eda_chart_cell_14_4.png)

Điều này cho thấy phần lớn repo có tín hiệu được cộng đồng quan tâm hoặc tái sử dụng ở một mức nhất định. Tương tự stars, forks có phân phối lệch phải: đa số repo nằm ở vùng thấp/trung bình, trong khi một số repo rất lớn tạo phần đuôi dài.

## 6. Phân phối size

Phân phối size không tập trung vào một khoảng duy nhất, mà chia thành nhiều cụm. Các nhóm nổi bật gồm:

![Repo count by size bucket](eda_report_images/eda_chart_cell_15_5.png)

- Repo rất nhỏ dưới 5MB.
- Repo trung bình trong khoảng 10-50MB.
- Sau mốc 50MB, số lượng repo giảm dần.

Có **368 repo nhỏ hơn 100KB**, chiếm **3.51%**. Nhóm này cần kiểm tra vì có khả năng là repo quá nhỏ, demo, template hoặc skeleton.

Ngược lại, có **616 repo lớn hơn 250MB**, chiếm **5.88%**, và **130 repo lớn hơn 1GB**, chiếm **1.24%**. Nhóm repo quá lớn không nhất thiết là kém chất lượng, nhưng có thể chứa asset, dataset, model, file sinh ra hoặc lịch sử Git lớn. Các repo này nên được audit riêng trước khi clone/chạy benchmark để tránh chi phí tải và xử lý quá lớn.

## 7. Template repo và các trường hợp cần audit

Trong tập metadata có **90 repo là template**, chiếm khoảng **0.86%**. Nhóm này nên được xem xét loại hoặc kiểm tra thủ công ở bước làm sạch, vì template repo thường không đại diện cho project ứng dụng thực tế.

Ngoài template repo, các nhóm cần audit thêm gồm:

- Repo thiếu `description`.
- Repo thiếu `license`.
- Repo không có `topics`.
- Repo nhỏ hơn 100KB.
- Repo lớn hơn 250MB hoặc 1GB.
- Repo có description có khả năng không phải tiếng Anh.

## 8. Kết luận sơ bộ

Tập metadata hiện tại có chất lượng nền khá tốt cho EDA giai đoạn đầu. Phần lớn repo thỏa các điều kiện quan trọng: public, Python, không fork, không archived, không disabled và có tín hiệu cộng đồng qua stars/forks.

Tuy nhiên, dữ liệu vẫn có một số điểm cần chú ý trước khi chọn tập benchmark cuối cùng. Các vấn đề chính gồm thiếu `topics`, thiếu `license`, một số description có khả năng không phải tiếng Anh, repo quá nhỏ, repo quá lớn và repo dạng template.

Ở bước tiếp theo, các tín hiệu này nên được dùng để tạo danh sách audit/làm sạch dữ liệu, thay vì loại bỏ tất cả một cách máy móc. Đặc biệt, `topics` và `homepage` là trường optional trên GitHub, nên chỉ nên xem là tín hiệu phụ. Các tiêu chí nên ưu tiên cho bước làm sạch tiếp theo là template repo, size quá nhỏ, license thiếu và các repo quá lớn có nguy cơ gây khó khăn khi clone/chạy benchmark.
