# GitHub Python Web Project Crawler

README nay mo ta cong cu crawl metadata repo GitHub de tao tap ung vien project benchmark Python web/backend.

## Muc tieu

Cong cu `collect_projects.py` dung GitHub Search Repositories API de tim cac repo Python public co tin hieu web/backend/API. Tool chi lay metadata repo GitHub tra ve, khong clone source code project.

Ket qua duoc dung cho giai doan 1 cua quy trinh benchmark:

- Tao pool candidate project.
- Luu raw metadata de truy vet nguon.
- Luu file filter gon hon de phuc vu loc, so sanh va giai thich vi sao repo duoc chon.

## File chinh

- `collect_projects.py`: crawler metadata repo GitHub.
- `github_search_raw_repos.json`: raw repo items tu GitHub Search API.
- `github_python_web_project_filter.json`: metadata rut gon va thong tin query match.
- `crawler_run.log`: log khi chay crawler.

## Dieu kien search nen

Moi query GitHub Search deu co cac dieu kien nen:

```text
language:Python
is:public
fork:false
archived:false
forks:>=50
```

`pushed` va `stars` khong dat co dinh thanh mot query lon, ma duoc chia thanh nhieu partition nho de tranh gioi han 1000 ket qua/query cua GitHub Search.

Mac dinh:

```text
active_months = 12
min_stars = 50
min_forks = 50
```

## Search string

Crawler chay lan luot cac search string sau:

```text
django in:readme,description
flask in:readme,description
fastapi in:readme,description
starlette in:readme,description
sanic in:readme,description
tornado in:readme,description
quart in:readme,description

backend in:readme,description
api in:readme,description
rest-api in:readme,description
web in:readme,description
web-service in:readme,description
microservice in:readme,description

topic:web
topic:backend
topic:api
topic:rest-api
topic:webapp
topic:web-application
```

Nhom framework giup bat cac project Python web ro rang. Nhom backend/web keyword giup bat cac repo khong ghi framework trong metadata. Nhom topic giup bo sung tin hieu web/backend do maintainer gan tren GitHub.

## Co che chia query

GitHub Search chi cho truy cap khoang 1000 ket qua dau cho moi query. Vi vay crawler khong gui mot query qua lon.

Moi search string duoc chia theo:

- Khoang `pushed` theo thang trong 12 thang gan nhat.
- Khoang `stars`, vi du `50..99`, `100..199`, `200..499`, `500..999`, `1000..4999`, `>=5000`.

Vi du query nho:

```text
django in:readme,description language:Python is:public fork:false archived:false forks:>=50 pushed:2026-06-01..2026-06-18 stars:1000..4999
```

Neu query nho van co `total_count` qua lon, crawler tiep tuc chia nho partition de lay du ket qua hon.

## Co che dung

Crawler dung khi da chay het:

```text
sort mode -> search string -> partition -> page
```

Cu the:

- Mot page dung khi GitHub tra het ket qua cua page do.
- Mot partition dung khi da lay het cac page can lay cua partition do.
- Mot search string dung khi da chay het tat ca partition.
- Toan bo crawler dung khi da chay het tat ca search string.

Mac dinh crawler khong dung theo so luong repo co dinh. `--limit 0` nghia la khong gioi han tong repo.

## Co che luu va resume

Crawler luu lien tuc sau moi repo moi hoac moi lan repo trung duoc merge them thong tin match.

Hai file output chinh:

```text
github_search_raw_repos.json
github_python_web_project_filter.json
```

Neu dung giua chung, chay lai `collect_projects.py` se doc file cu:

- Repo moi thi them vao file.
- Repo da co thi khong tao ban ghi trung.
- Neu repo cu match them search string/partition moi thi merge them vao filter metadata.

## Cach chay

Can set `GITHUB_TOKEN` truoc khi chay de tranh rate limit thap.

Chay co log:

```powershell
python -u collect_projects.py 2>&1 | Tee-Object -FilePath crawler_run.log
```

Ghi tiep vao log cu:

```powershell
python -u collect_projects.py 2>&1 | Tee-Object -FilePath crawler_run.log -Append
```

Kiem tra crawler con chay khong:

```powershell
Get-Process python -ErrorAction SilentlyContinue
```

Kiem tra file output co cap nhat khong:

```powershell
Get-Item .\github_search_raw_repos.json, .\github_python_web_project_filter.json
```
