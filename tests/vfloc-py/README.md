# vfloc-py — Định vị hàm chứa lỗ hổng trong code Python

Phiên bản viết lại của VFArchē:

- ✅ Phân tích **mã nguồn Python** (không phải Java) bằng `ast` chuẩn của Python.
- ✅ Mọi bước cần LLM đều **gọi OpenAI API** — không tải model về.
- ✅ App chạy **native trên Windows** (Python venv). **Không cần build Docker** cho app — chỉ MongoDB chạy trong Docker.

> Project gốc (Java + CodeBERT local + Docker app) vẫn còn ở thư mục cha (`../`) để tham khảo, không bị xóa.

---

## 🚀 Quick Start — chạy ngay 1 CVE

> Nếu **mới clone repo lần đầu**, làm tuần tự **A → B**. Nếu **đã setup rồi**, nhảy thẳng đến **B**.

### A. Setup (làm đúng 1 lần)

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py

# 1. Bật MongoDB qua Docker (Docker Desktop phải đang chạy)
docker compose up -d mongo

# 2. Tạo venv + cài dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 3. Tạo .env
Copy-Item .env.example .env
# → Nếu chưa có key thì để trống và chạy với --skip-llm.
```

### B. Run (mỗi lần muốn chạy 1 CVE)

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py
.\.venv\Scripts\Activate.ps1

# 1. Chạy pipeline (chọn 1 trong 2)
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --skip-llm    # miễn phí
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681               # +LLM, ~$0.005

# 2. Xem top-20
python scripts\view_topk.py --cve CVE-2023-32681
```

**Kỳ vọng output**: hàm vá lỗi thật `rebuild_proxies` lọt vào top-20 (test thực tế lần đầu: rank #3 trên 643 hàm với chỉ BM25).

> Chi tiết từng bước, dataset format, các cách xem kết quả khác, xử lý sự cố — đọc các mục bên dưới.

---

## Pipeline

```
JSONL dataset ──▶ Clone repo ──▶ Parse Python AST ──▶ BM25 (top 100) ──▶ LLM Rerank (top 20) ──▶ MongoDB
                  (gitpython)     (ast.walk)          (rank-bm25)        (gpt-4o-mini)
```

MVP hiện tại bỏ qua: CWE expansion, Tracker (call graph/dataflow), Classifier fine-tune. Xem [phần cuối](#mở-rộng-sau-mvp) để thêm sau.

---

## Yêu cầu

| Thành phần | Yêu cầu |
|---|---|
| Python | 3.10+ |
| Docker Desktop | Chỉ để chạy MongoDB |
| Git | Để clone repo CVE |
| LLM API key | **OpenAI** ([key](https://platform.openai.com/api-keys), $0.005/CVE) HOẶC **OpenRouter** ([key](https://openrouter.ai/keys), có model FREE). Không có key → dùng `--skip-llm`. |

---

## Cài đặt (làm 1 lần)

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py

# 1. Bật MongoDB qua Docker
docker compose up -d mongo

# 2. Tạo Python virtual environment
python -m venv .venv

# 3. Kích hoạt venv
.\.venv\Scripts\Activate.ps1
# Nếu báo lỗi "running scripts is disabled":
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   rồi gõ lại lệnh activate

# 4. Cài dependencies
pip install -r requirements.txt

# 5. Tạo .env từ template
Copy-Item .env.example .env
# Nếu chưa dùng LLM thì để OPENAI_API_KEY/OPENROUTER_API_KEY trống và chạy --skip-llm.
```

---

## Chạy thủ công — từng bước

### Bước 1 — Kiểm tra MongoDB đang chạy

```powershell
docker ps
# Phải thấy 1 trong 2:
#   vfloc-py-mongo  Up ...  0.0.0.0:27017->27017/tcp   (container mới)
#   vfloc-mongo     Up ...  0.0.0.0:27017->27017/tcp   (container cũ — vẫn dùng được)
```

Nếu không thấy: `docker compose up -d mongo` (trong thư mục `vfloc-py/`).

### Bước 2 — Kích hoạt venv

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py
.\.venv\Scripts\Activate.ps1
```

Dấu nhắc đổi thành `(.venv) PS D:\...\vfloc-py>` là OK.

### Bước 3 — Chọn 1 CVE từ dataset

Liệt kê 10 CVE đầu:

```powershell
python -c "import sys; sys.path.insert(0,'.'); from vfloc.data.load_cve import load; [print(c['cve_id'], '-', c['repo_url']) for c in load('../data-new/data-new.jsonl')[:10]]"
```

Hoặc dùng 1 CVE đã verify chạy ngon (repo nhỏ, vài giây):

| CVE | Repo | Ground-truth function |
|---|---|---|
| `CVE-2023-32681` | `psf/requests` | `rebuild_proxies` |
| `CVE-2021-33503` | `urllib3/urllib3` | `parse_url` |
| `CVE-2016-9015` | `urllib3/urllib3` | `verify_mode` |

### Bước 4 — Chạy pipeline

**Cách miễn phí — chỉ BM25:**
```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --skip-llm
```

**Cách đầy đủ — BM25 + LLM rerank (~$0.005/CVE):**
```powershell
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681
```

Log mẫu khi chạy:
```
=== CVE-2023-32681 | https://github.com/psf/requests ===
  cloned/checked out at: ...\repo_cache\requests
  total functions parsed: 643
  BM25 top-100 computed
  LLM top-20 computed
  saved top-20 to MongoDB.
  ground-truth hits: ['rebuild_proxies'] / ['rebuild_proxies']
```

### Bước 5 — Xem kết quả top-k

Chọn 1 trong 4 cách:

#### A. Script tiện sẵn (nhanh nhất)
```powershell
python scripts\view_topk.py --cve CVE-2023-32681
```

#### B. Export ra file JSON
```powershell
python -c "from pymongo import MongoClient; import json, os; os.makedirs('logs', exist_ok=True); doc=MongoClient('mongodb://localhost:27017')['vfloc_py']['topk_results'].find_one({'cve_id':'CVE-2023-32681'}); doc.pop('_id',None); open('logs/CVE-2023-32681.json','w',encoding='utf-8').write(json.dumps(doc, indent=2, ensure_ascii=False)); print('Saved logs/CVE-2023-32681.json')"
```

Mở file [logs/CVE-2023-32681.json](logs/CVE-2023-32681.json) trong VSCode để xem.

#### C. Mongosh trong Docker Desktop
1. Docker Desktop → Containers → `vfloc-mongo` (hoặc `vfloc-py-mongo`) → tab **Exec**
2. Gõ thẳng `mongosh` (KHÔNG gõ `docker exec` — đã ở trong container rồi).
3. Trong mongosh:
   ```js
   use vfloc_py
   db.topk_results.find({cve_id: "CVE-2023-32681"}).pretty()
   ```

#### D. MongoDB Compass (GUI trực quan)
Cài [MongoDB Compass](https://www.mongodb.com/products/compass) → kết nối `mongodb://localhost:27017` → database `vfloc_py` → collection `topk_results`.

---

## Cheat sheet (sao chép nguyên cụm)

```powershell
cd D:\Capstone\VFARCHE\vulnerability_localization-C-2DD2\vfloc-py
docker compose up -d mongo
.\.venv\Scripts\Activate.ps1
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 --skip-llm
python scripts\view_topk.py --cve CVE-2023-32681
```

5 lệnh, ra top-20 ngay.

---

## Tất cả flag của CLI

| Flag | Tác dụng |
|---|---|
| `--dataset PATH` (bắt buộc) | File CSV/JSON/JSONL dataset |
| `--cve CVE-XXXX` | Chỉ chạy 1 CVE. Bỏ flag = chạy toàn bộ 543 CVE |
| `--skip-llm` | Dừng sau BM25, không gọi LLM (miễn phí) |
| `--no-cache` | Bỏ cache hàm cũ, parse lại repo từ đầu |
| `--provider {openai,openrouter}` | Đổi LLM provider (override `.env`) |
| `--model NAME` | Đổi chat model (override `.env`) |
| `--rerank {chat,embedding}` | Cách rerank: **chat** (LLM chấm 0-10) hoặc **embedding** (cosine similarity). Mặc định `chat`. |
| `--embedding-model NAME` | Đổi embedding model (chỉ áp dụng khi `--rerank embedding`) |

### Hai cách rerank

| Mode | Mô tả | Model mặc định (OpenRouter) | Tốc độ | Đã verify |
|---|---|---|---|---|
| `chat` | LLM đọc CVE + hàm, chấm điểm 0-10 | `openai/gpt-oss-120b:free` | Chậm hơn (10 hàm/request) | ✓ |
| `embedding` | Cosine similarity giữa embedding CVE và embedding hàm | `nvidia/llama-nemotron-embed-vl-1b-v2:free` | Nhanh (16 hàm/request) — 11s cho 100 hàm | ✓ trên `requests`, hit `rebuild_proxies` #3 |

> Cả 2 mode đều **dùng chung 1 API key** trong `.env` (chỉ cần `OPENROUTER_API_KEY` nếu `LLM_PROVIDER=openrouter`). Model chat & embedding cấu hình độc lập (`OPENROUTER_MODEL` và `OPENROUTER_EMBEDDING_MODEL`).

---

## 🌐 Chọn LLM provider

Hỗ trợ **OpenAI** và **OpenRouter** (cả hai dùng chung API OpenAI-compatible — chỉ đổi `base_url` + key).

### Cấu hình trong `.env`

```env
LLM_PROVIDER=openai             # hoặc openrouter

# OpenAI
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini

# OpenRouter
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-oss-120b:free
```

### Hoặc override bằng CLI (không cần sửa `.env`)

```powershell
# Dùng OpenRouter với model Llama 3.3 70B free
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 `
    --provider openrouter --model "openai/gpt-oss-120b:free"

# Dùng OpenAI gpt-4o (đắt hơn nhưng chính xác hơn)
python -m vfloc.cli run --dataset ..\data-new\data-new.jsonl --cve CVE-2023-32681 `
    --provider openai --model "gpt-4o"
```

### So sánh nhanh

| Provider | Đăng ký key | Chi phí | Khi nào nên dùng |
|---|---|---|---|
| **OpenAI** | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | $0.005/CVE (gpt-4o-mini) | Khi đã có credit OpenAI |
| **OpenRouter** | [openrouter.ai/keys](https://openrouter.ai/keys) | **Có model FREE** (Llama 3.3 70B, DeepSeek, Gemini Flash...) | Khi OpenAI hết quota, hoặc muốn so sánh nhiều model |

> **Mẹo:** OpenRouter free model có rate limit ~10-20 request/phút. Pipeline batch 10 hàm/request → 1 CVE chạy hết ~30s. Đủ cho dev/test.

### Model OpenRouter free phổ biến

| Model ID | Note |
|---|---|
| `openai/gpt-oss-120b:free` | Llama 3.3 70B — chất lượng cao, mặc định |
| `deepseek/deepseek-chat-v3.1:free` | DeepSeek V3.1 — mạnh về code |
| `google/gemini-2.0-flash-exp:free` | Gemini 2.0 Flash — nhanh |
| `qwen/qwen-2.5-72b-instruct:free` | Qwen 2.5 72B — đa ngôn ngữ |

Xem danh sách mới nhất: <https://openrouter.ai/models?supported_parameters=tools&max_price=0>

---

## Format dataset CVE

Loader (`vfloc/data/load_cve.py`) hỗ trợ **JSONL / JSON / CSV** và **2 schema** (tự nhận theo tên field). Các dòng cùng `cve_id` được **gộp lại** (union `fixed_funcs`).

### Schema 1 — JSONL đang dùng (`data-new/data-new.jsonl`)

| Field | Bắt buộc | Ý nghĩa |
|---|---|---|
| `cve_id` | ✅ | vd `CVE-2020-26257` |
| `description` | ✅ | Mô tả CVE |
| `repo_url` | ✅ | URL repo GitHub |
| `commit_sha` |   | SHA commit vá lỗi → map sang `patch_commit` |
| `all_functions` (list) |   | Tên các hàm vá lỗi → map sang `fixed_funcs` |
| `vf_file` |   | File chứa hàm lỗi (chỉ dùng verify) |
| Các field khác (severity, cvss_*, cwes, packages, references...) | | Bỏ qua |

### Schema 2 — Canonical CSV

| Field | Bắt buộc |
|---|---|
| `cve_id` | ✅ |
| `description` | ✅ |
| `repo_url` | ✅ |
| `patch_commit` |   |
| `fixed_funcs` (string, ngăn phẩy) |   |

---

## Cấu trúc thư mục

```
vulnerability_localization-C-2DD2/      # ROOT
├── data-new/                           # ⭐ dataset mới (cùng cấp main/)
│   └── data-new.jsonl                  # 543 CVE Python unique
├── main/, utils/, libs/ ...             # ← project Java cũ (giữ tham khảo)
└── vfloc-py/                           # ⭐ project Python mới
    ├── config.py                       # OPENAI_MODEL, MONGO_URI, BM25_TOP_K, LLM_TOP_K
    ├── docker-compose.yml              # chỉ service mongo
    ├── requirements.txt
    ├── .env.example                    # template — copy thành .env, dán key vào
    ├── .env                            # ← file thật (bị .gitignore)
    ├── repo_cache/                     # repo đã clone (bị .gitignore)
    ├── logs/                           # JSON export (bị .gitignore)
    │
    ├── vfloc/
    │   ├── cli.py                      # entry: python -m vfloc.cli run --dataset ...
    │   ├── parser/
    │   │   ├── python_parser.py        # ast.walk lấy mọi FunctionDef/AsyncFunctionDef
    │   │   └── repo_cloner.py          # git clone vào repo_cache/
    │   ├── ranking/
    │   │   ├── bm25_rank.py            # rank_bm25 + CamelCase/snake_case tokenizer
    │   │   └── llm_compare.py          # gpt-4o-mini batch score 10 hàm/lần
    │   ├── llm/
    │   │   ├── client.py               # OpenAI client + retry (tenacity)
    │   │   └── prompts.py              # template prompt
    │   ├── storage/
    │   │   └── mongo.py                # pymongo wrapper
    │   └── data/
    │       └── load_cve.py             # đọc CSV/JSON/JSONL, dedup theo cve_id
    │
    └── scripts/
        └── view_topk.py                # in top-k cho 1 hoặc mọi CVE
```

---

## Kết quả MongoDB

Sau khi chạy, dữ liệu nằm trong database **`vfloc_py`** (khác với DB `vfloc` của project Java cũ — không đụng).

| Collection | Nội dung |
|---|---|
| `topk_results` | 1 doc/CVE — chứa `cve_id`, `repo`, `total_funcs`, `topk` (list 20 hàm đã rerank) |
| `func_cache` | 1 doc/CVE — cache toàn bộ hàm đã parse (để rerun không phải parse lại) |

Mỗi item trong `topk`:
```json
{
  "rank": 3,
  "name": "rebuild_proxies",
  "qualname": "SessionRedirectMixin.rebuild_proxies",
  "file": "requests/sessions.py",
  "start_line": 303,
  "bm25_score": 345.18,
  "llm_score": null
}
```

---

## Chi phí OpenAI (`gpt-4o-mini`)

- Pricing: $0.15/1M input tokens, $0.60/1M output tokens
- 1 CVE = 100 hàm BM25 / batch 10 hàm = 10 request × ~3K input + 50 output → ~$0.0005/request
- **≈ $0.005 / CVE (~125 VNĐ)** với LLM rerank đầy đủ
- `--skip-llm` → **miễn phí** (chỉ BM25 local)

> Đổi model trong [.env](.env): `OPENAI_MODEL=gpt-4o` (chính xác hơn ~17× chi phí) hoặc giữ default `gpt-4o-mini`.

---

## Xử lý sự cố

| Triệu chứng | Nguyên nhân & fix |
|---|---|
| `failed to connect to the docker API` | Docker Desktop chưa chạy. Mở Docker Desktop, đợi icon xanh. |
| `running scripts is disabled` khi `Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `ModuleNotFoundError: No module named 'pymongo'` | Quên kích hoạt venv hoặc chưa `pip install -r requirements.txt`. |
| `AuthenticationError` từ OpenAI/OpenRouter | Key sai, key trống, hoặc provider/model chưa đúng. |
| `RateLimitError: insufficient_quota` | Tài khoản OpenAI hết credit. Nạp tại https://platform.openai.com/settings/organization/billing — tối thiểu $5. Tạm dùng `--skip-llm`. |
| Mongosh mở ra thấy startup warnings | Đó là warning bình thường (XFS, no auth) — KHÔNG phải lỗi. Cứ gõ `use vfloc_py` rồi query. |
| Repo clone bị treo | Repo quá lớn. Ctrl+C rồi thử CVE có repo nhỏ hơn (xem bảng ở Bước 3). |

---

## Mở rộng sau MVP

| Module | Tác dụng | Vị trí dự kiến |
|---|---|---|
| CWE-1000 enrich | Mở rộng mô tả CVE bằng CWE | `vfloc/expansion/cwe_enrich.py` |
| Pseudo Relevance Feedback | Mở rộng truy vấn bằng PRF + BM25 | `vfloc/expansion/pseudo_relevance.py` |
| Tracker (call graph) | Patch-present mode — phân tích call graph | `vfloc/tracker/call_graph.py` |
| Dataflow analysis | Patch-present mode — data flow trên AST | `vfloc/tracker/dataflow.py` |
| Classifier fine-tune | Gọi OpenAI Fine-tuning API thay CodeBERT | `vfloc/llm/fine_tune.py` |
| Swiss-System ranking | Top-100 → Top-20 hiệu quả hơn pairwise | `vfloc/ranking/swiss_system.py` |
| Web UI | Xem top-k đẹp hơn Mongo Compass | `vfloc/web/` |

---

## Tham khảo

- Project gốc Java + giản đồ kiến trúc: thư mục cha (`../`) và `../README.md`
- Dataset: [`../data-new/data-new.jsonl`](../data-new/data-new.jsonl) — 543 CVE Python unique
