# VFLoc - Vulnerability Function Localization

VFLoc là bộ công cụ định vị hàm có khả năng chứa lỗ hổng bảo mật từ mô tả CVE.

Repo hiện có 2 phần:

- `vfloc-py/`: bản Python mới, dùng cho dataset Python trong `data-new/data-new.jsonl`. Đây là luồng khuyến nghị để chạy demo/thử nghiệm hiện tại.
- Thư mục gốc: bản legacy cho Java/Maven, chạy bằng Docker. Luồng này cần các file CSV trong thư mục `data/`; nếu clone sạch mà thiếu `data/XXXX-3 data - filtered_cve_with_link.csv` thì chưa chạy được.

## Trạng thái hiện tại

Phần nên dùng ngay là `vfloc-py/`.

Đã kiểm tra nhanh:

- `python -m vfloc.cli --help` chạy được trong virtualenv của `vfloc-py`.
- `python scripts/view_topk.py --help` chạy được.
- Docker và Docker Compose có sẵn trên máy.
- Root Java/Docker chưa nên coi là sẵn sàng nếu thiếu thư mục `data/`.

## Secret cần xóa hoặc rotate

Không commit file `.env`. Các file `.env` đã được `.gitignore` bỏ qua, nhưng vẫn nên kiểm tra trước khi push.

Các secret cần xử lý:

1. `vfloc-py/.env`
   - Nếu từng dán `OPENROUTER_API_KEY` thật vào file này, hãy xóa khỏi file local trước khi chia sẻ repo.
   - Nên rotate key trên OpenRouter vì key đã từng nằm trong workspace local.

2. `.env`
   - Nếu từng dán `OPENAI_API_KEY`, `MONGO_USER`, `MONGO_PWD`, `MONGO_AUTH` thật thì xóa khỏi file trước khi nén/chia sẻ.
   - Nếu key đã từng commit/push lên remote thì phải revoke/rotate trên dashboard provider.

3. `scripts/get_qingwen_data.py`
   - File này trước đây có hard-code MongoDB password. Code đã đổi sang biến môi trường:
     - `QINGWEN_MONGO_USER`
     - `QINGWEN_MONGO_PWD`
     - `QINGWEN_MONGO_AUTH`
   - Nếu password đó là credential thật, hãy đổi mật khẩu ở phía MongoDB server.

Các giá trị dạng `OPENAI_API_KEY=` hoặc `OPENROUTER_API_KEY=` để trống trong `.env.example` là đúng, không phải secret.

## Cách chạy bản Python khuyến nghị

### 1. Yêu cầu

- Windows 10/11
- Python 3.10+
- Git
- Docker Desktop, chỉ dùng để chạy MongoDB
- API key là tùy chọn:
  - Không có key: chạy BM25 miễn phí bằng `--skip-llm`
  - Có key: dùng OpenAI hoặc OpenRouter để rerank top-k

### 2. Vào thư mục app

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py
```

Nếu dùng đường dẫn khác, thay phần `D:\Capstone\...` bằng đường dẫn repo trên máy bạn.

### 3. Bật MongoDB

```powershell
docker compose up -d mongo
```

Kiểm tra:

```powershell
docker ps --format "{{.Names}}`t{{.Status}}"
```

Cần thấy container `vfloc-py-mongo` hoặc một MongoDB container đang `Up`.

### 4. Tạo virtualenv và cài thư viện

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Nếu PowerShell chặn activate script:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 5. Tạo file `.env`

```powershell
Copy-Item .env.example .env
```

Chạy miễn phí thì để key trống và dùng `--skip-llm`.

Nếu dùng OpenRouter:

```env
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-oss-120b:free
OPENROUTER_EMBEDDING_MODEL=nvidia/llama-nemotron-embed-vl-1b-v2:free
```

Nếu dùng OpenAI:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_EMBEDDING_MODEL=text-embedding-3-small
```

Không commit file `.env`.

### 6. Chạy thử 1 CVE bằng BM25 miễn phí

```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --skip-llm
```

Kỳ vọng log chính:

```text
=== CVE-2023-32681 | https://github.com/psf/requests ===
total functions parsed: ...
BM25 top-100 computed
rerank top-20 computed
saved top-20 to MongoDB.
```

### 7. Chạy với LLM rerank

Chat rerank:

```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681
```

Embedding rerank:

```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --rerank embedding
```

Override provider/model từ CLI:

```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --provider openrouter --model "openai/gpt-oss-120b:free"
```

### 8. Xem kết quả top-k

```powershell
python scripts\view_topk.py --cve CVE-2023-32681
```

Hoặc xem bằng MongoDB Compass:

- URI: `mongodb://localhost:27017`
- Database: `vfloc_py`
- Collection: `topk_results`

## Cheat sheet

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py
docker compose up -d mongo
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --skip-llm
python scripts\view_topk.py --cve CVE-2023-32681
```

## CLI flags

| Flag | Ý nghĩa |
|---|---|
| `--dataset PATH` | Dataset CSV/JSON/JSONL, bắt buộc |
| `--cve CVE-ID` | Chỉ chạy một CVE; bỏ flag này để chạy toàn bộ dataset |
| `--skip-llm` | Chỉ dùng BM25, không gọi API |
| `--no-cache` | Parse lại repo, bỏ cache function cũ |
| `--rerank chat` | Dùng chat model để chấm điểm top-k |
| `--rerank embedding` | Dùng embedding model để rerank |
| `--provider openai` | Dùng OpenAI |
| `--provider openrouter` | Dùng OpenRouter |
| `--model NAME` | Override chat model |
| `--embedding-model NAME` | Override embedding model |

## Dataset

Dataset Python hiện nằm ở:

```text
data-new/data-new.jsonl
```

Mỗi record cần có tối thiểu:

- `cve_id`
- `repo_url`
- `commit_sha` hoặc thông tin commit tương đương
- `description`
- `vf_function` hoặc danh sách function ground-truth

## Xử lý lỗi thường gặp

| Lỗi | Cách xử lý |
|---|---|
| `API key ... chua duoc set` | Thêm key vào `.env` hoặc chạy với `--skip-llm` |
| Không kết nối được MongoDB | Chạy `docker compose up -d mongo` trong `vfloc-py/` |
| `running scripts is disabled` khi activate venv | Chạy `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| Repo clone chậm hoặc lỗi mạng | Chạy lại lệnh; repo được cache trong `vfloc-py/repo_cache/` |
| Kết quả cũ không đổi | Thêm `--no-cache` để parse lại |

## Bản legacy Java/Docker ở thư mục gốc

Chỉ dùng phần này khi bạn có đủ dataset CSV legacy trong `data/`.

Các file code legacy đang đọc những đường dẫn như:

```text
data/XXXX-3 data - filtered_cve_with_link.csv
data/XXXX-3 data - real-world.csv
data/filtered_cve_with_link.csv
data/real-world.csv
```

Nếu thiếu các file trên, `docker compose up app` ở thư mục gốc sẽ không chạy đúng.

Luồng legacy cơ bản:

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2
Copy-Item .env.example .env
docker compose build
docker compose up -d mongo
docker compose up app
```

Cấu hình an toàn nhất cho legacy:

```python
re_rank_approach_choice = 'bm25'
retrieval_approach_choice = 'no_filter'
query_expansion_choice = 'description_only'
dataset = 'benchmark'
```

Kết quả legacy nằm trong MongoDB:

- Database: `vfloc`
- Collection: `no_filter__description_only__bm25`

## Checklist trước khi push/chia sẻ repo

```powershell
git status --short
rg -n --hidden "sk-|OPENAI_API_KEY=.+|OPENROUTER_API_KEY=.+|password=|MONGO_PWD=.+" -g "!.git/**"
```

Kỳ vọng:

- Không có key thật trong output.
- `.env` và `vfloc-py/.env` không xuất hiện trong file đã stage.
- README không còn conflict marker `<<<<<<<`, `=======`, `>>>>>>>`.
