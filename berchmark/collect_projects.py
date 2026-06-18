import argparse
import calendar
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


"""
Crawler metadata repo GitHub cho giai doan 1.

Muc tieu:
- Khong clone project.
- Chi dung GitHub Search API de lay metadata repo.
- Luu raw metadata dung gan voi object GitHub tra ve.
- Luu rieng file filter metadata de phuc vu so sanh, loc va giai thich vi sao repo duoc bat.
- Dieu kien "web" khong co qualifier rieng tren GitHub Search, nen duoc dat trong search string:
  framework web nhu django/fastapi/flask, hoac term backend/api/web/rest-api.

Ket qua:
- github_search_raw_repos.json: raw repo items tu GitHub Search.
- github_python_web_project_filter.json: metadata rut gon + search string/query match.
"""


GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

# Header GitHub API. Neu co GITHUB_TOKEN thi them Authorization de tang rate limit.
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


# Cac framework Python web/backend dung de tao search string chinh.
# Day la web signal manh vi ban than cac framework nay thuoc web/backend/API stack.
# Mac dinh moi framework tao 1 query dang: django in:readme,description.
FRAMEWORK_TERMS = [
    "django",
    "flask",
    "fastapi",
    "starlette",
    "sanic",
    "tornado",
    "quart",
]

# Cac tu khoa backend/web tong quat de mo rong pool candidate.
# Day la web signal truc tiep cho cac repo khong ghi ro framework.
# Mac dinh moi term tao 1 query dang: backend in:readme,description.
BACKEND_WEB_TERMS = [
    "backend",
    "api",
    "rest-api",
    "web",
    "web-service",
    "microservice",
]

# Topic search giup bat cac repo co tin hieu web/app/domain.
TOPIC_TERMS = [
    "web",
    "backend",
    "api",
    "rest-api",
    "webapp",
    "web-application"
]

NEGATIVE_TERMS = [
    "template",
    "boilerplate",
    "cookiecutter",
]


class SkipRequest(Exception):
    """Bao hieu request nen bi bo qua thay vi lam dung ca qua trinh crawl."""

    pass


def github_get(path_or_url: str, max_rate_limit_sleep: int, **params: Any) -> Any:
    """Goi GitHub API, xu ly retry nhe va rate limit."""

    # Goi GitHub API bang thu vien chuan de script khong phu thuoc package ngoai.
    url = path_or_url if path_or_url.startswith("http") else f"{GITHUB_API}{path_or_url}"
    if params:
        url = f"{url}?{urlencode(params)}"

    for attempt in range(1, 4):
        try:
            request = Request(url, headers=HEADERS)
            with urlopen(request, timeout=20) as response:
                payload = response.read().decode("utf-8")
                return json.loads(payload)
        except HTTPError as exc:
            # Neu cham rate limit va thoi gian doi ngan, cho roi thu lai.
            if exc.code in {403, 429}:
                remaining = exc.headers.get("X-RateLimit-Remaining")
                reset = exc.headers.get("X-RateLimit-Reset")
                if remaining == "0" and reset:
                    sleep_for = max(1, int(reset) - int(time.time()) + 3)
                    if sleep_for > max_rate_limit_sleep:
                        raise SkipRequest(f"GitHub rate limit requires waiting {sleep_for}s.")
                    print(f"Rate limit reached. Sleeping {sleep_for}s...")
                    time.sleep(sleep_for)
                    continue
            if attempt == 3:
                raise SkipRequest(f"GitHub HTTP {exc.code}: {exc.reason}")
            time.sleep(attempt * 2)
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == 3:
                raise SkipRequest(f"Request failed after retries: {exc}")
            time.sleep(attempt * 2)

    raise SkipRequest(f"Could not fetch {url}")


def pushed_after_date(active_months: int) -> str:
    """Tinh ngay toi thieu cho dieu kien pushed:>= theo so thang gan day."""

    # Chuyen dieu kien "active trong N thang" thanh pushed:>=YYYY-MM-DD.
    today = datetime.now(timezone.utc).date()
    month = today.month - active_months
    year = today.year
    while month <= 0:
        month += 12
        year -= 1
    return today.replace(year=year, month=month).isoformat()


def add_months(year: int, month: int, delta: int) -> tuple[int, int]:
    """Cong/tru thang cho cap year/month."""

    month_index = (year * 12 + month - 1) + delta
    return month_index // 12, month_index % 12 + 1


def build_pushed_windows(active_months: int) -> list[str]:
    """Chia dieu kien pushed thanh tung thang de tranh gioi han 1000 ket qua/query."""

    if active_months <= 0:
        return []

    today = datetime.now(timezone.utc).date()
    start = datetime.fromisoformat(pushed_after_date(active_months)).date()
    windows = []
    year, month = start.year, start.month

    while True:
        _, last_day = calendar.monthrange(year, month)
        window_start = max(start, datetime(year, month, 1).date())
        window_end = min(today, datetime(year, month, last_day).date())
        if window_start <= window_end:
            windows.append(f"pushed:{window_start.isoformat()}..{window_end.isoformat()}")
        if year == today.year and month == today.month:
            break
        year, month = add_months(year, month, 1)

    return windows


def build_star_buckets(min_stars: int) -> list[dict[str, int | None]]:
    """Chia stars thanh cac khoang nho de lay du hon 1000 ket qua dau cua GitHub Search."""

    if min_stars <= 0:
        return [
            {"star_min": 10, "star_max": 49},
            {"star_min": 50, "star_max": 99},
            {"star_min": 100, "star_max": 199},
            {"star_min": 200, "star_max": 499},
            {"star_min": 500, "star_max": 999},
            {"star_min": 1000, "star_max": 4999},
            {"star_min": 5000, "star_max": None},
        ]

    buckets: list[dict[str, int | None]] = []
    ranges = [
        (10, 49),
        (50, 99),
        (100, 199),
        (200, 499),
        (500, 999),
        (1000, 4999),
    ]

    for low, high in ranges:
        if high < min_stars:
            continue
        buckets.append({"star_min": max(low, min_stars), "star_max": high})

    if min_stars <= 5000:
        buckets.append({"star_min": 5000, "star_max": None})
    else:
        buckets.append({"star_min": min_stars, "star_max": None})

    return buckets


def star_condition(star_min: int, star_max: int | None) -> str:
    """Doi khoang stars thanh qualifier GitHub Search."""

    if star_max is None:
        return f"stars:>={star_min}"
    return f"stars:{star_min}..{star_max}"


def make_partition(
    pushed_start: str | None,
    pushed_end: str | None,
    star_min: int,
    star_max: int | None,
) -> dict[str, Any]:
    """Tao partition day du metadata de co the chia nho tiep neu can."""

    conditions = [star_condition(star_min, star_max)]
    pushed_condition = None
    if pushed_start and pushed_end:
        pushed_condition = f"pushed:{pushed_start}..{pushed_end}"
        conditions.insert(0, pushed_condition)

    return {
        "conditions": conditions,
        "pushed_start": pushed_start,
        "pushed_end": pushed_end,
        "pushed_condition": pushed_condition,
        "star_min": star_min,
        "star_max": star_max,
        "star_condition": star_condition(star_min, star_max),
    }


def split_partition(partition: dict[str, Any]) -> list[dict[str, Any]]:
    """Chia partition lon thanh 2 partition nho hon de tranh tran 1000 ket qua/query."""

    pushed_start = partition.get("pushed_start")
    pushed_end = partition.get("pushed_end")
    star_min = int(partition["star_min"])
    star_max = partition.get("star_max")

    if pushed_start and pushed_end:
        start_date = datetime.fromisoformat(pushed_start).date()
        end_date = datetime.fromisoformat(pushed_end).date()
        if start_date < end_date:
            middle = start_date + (end_date - start_date) // 2
            right_start = middle + timedelta(days=1)
            return [
                make_partition(start_date.isoformat(), middle.isoformat(), star_min, star_max),
                make_partition(right_start.isoformat(), end_date.isoformat(), star_min, star_max),
            ]

    if star_max is None:
        split_at = max(star_min + 1, star_min * 2)
        return [
            make_partition(pushed_start, pushed_end, star_min, split_at - 1),
            make_partition(pushed_start, pushed_end, split_at, None),
        ]

    if star_min < star_max:
        middle_star = (star_min + star_max) // 2
        return [
            make_partition(pushed_start, pushed_end, star_min, middle_star),
            make_partition(pushed_start, pushed_end, middle_star + 1, star_max),
        ]

    return []


def build_base_conditions(min_forks: int = 50, use_negative_terms: bool = False) -> list[str]:
    """Tao cac dieu kien loc nen duoc gan vao moi GitHub Search query."""

    # Dieu kien nen ap dung cho moi query GitHub Search.
    # pushed va stars duoc tach thanh query partitions de vuot gioi han 1000 ket qua/query.
    conditions = [
        "language:Python",
        "is:public",
        "fork:false",
        "archived:false",
    ]
    if min_forks > 0:
        conditions.append(f"forks:>={min_forks}")
    if use_negative_terms:
        conditions.extend(f"-{term}" for term in NEGATIVE_TERMS)
    return conditions


def build_query_partitions(min_stars: int, active_months: int) -> list[dict[str, Any]]:
    """Tao cac partition stars/pushed de moi query nho hon va lay du ket qua hon."""

    pushed_windows = build_pushed_windows(active_months)
    if not pushed_windows:
        pushed_windows = [None]

    star_buckets = build_star_buckets(min_stars)
    partitions = []

    for pushed_condition in pushed_windows:
        pushed_start = None
        pushed_end = None
        if pushed_condition:
            pushed_range = pushed_condition.removeprefix("pushed:")
            pushed_start, pushed_end = pushed_range.split("..", 1)
        for star_bucket in star_buckets:
            conditions = [star_condition(star_bucket["star_min"], star_bucket["star_max"])]
            if pushed_condition:
                conditions.insert(0, pushed_condition)
            partition = make_partition(
                pushed_start,
                pushed_end,
                star_bucket["star_min"],
                star_bucket["star_max"],
            )
            partition["conditions"] = conditions
            partitions.append(partition)

    return partitions


def build_search_specs(
    include_backend_terms: bool,
    include_topic_terms: bool,
    split_scopes: bool,
) -> list[dict[str, str]]:
    """Tao danh sach search string can chay tren GitHub Search."""

    # Moi search spec gom term, scope va search_string de luu lai ly do repo duoc bat.
    specs: list[dict[str, str]] = []

    for term in FRAMEWORK_TERMS:
        if split_scopes:
            specs.append(
                {
                    "term": term,
                    "scope": "readme",
                    "search_string": f"{term} in:readme",
                    "web_signal": "framework",
                }
            )
            specs.append(
                {
                    "term": term,
                    "scope": "description",
                    "search_string": f"{term} in:description",
                    "web_signal": "framework",
                }
            )
        else:
            specs.append(
                {
                    "term": term,
                    "scope": "readme,description",
                    "search_string": f"{term} in:readme,description",
                    "web_signal": "framework",
                }
            )

    if include_backend_terms:
        for term in BACKEND_WEB_TERMS:
            if split_scopes:
                specs.append(
                    {
                        "term": term,
                        "scope": "readme",
                        "search_string": f"{term} in:readme",
                        "web_signal": "backend_web_keyword",
                    }
                )
                specs.append(
                    {
                        "term": term,
                        "scope": "description",
                        "search_string": f"{term} in:description",
                        "web_signal": "backend_web_keyword",
                    }
                )
            else:
                specs.append(
                    {
                        "term": term,
                        "scope": "readme,description",
                        "search_string": f"{term} in:readme,description",
                        "web_signal": "backend_web_keyword",
                    }
                )

    if include_topic_terms:
        for term in TOPIC_TERMS:
            specs.append(
                {
                    "term": term,
                    "scope": "topic",
                    "search_string": f"topic:{term}",
                    "web_signal": "topic",
                }
            )

    return specs


def build_query(base_conditions: list[str], search_string: str) -> str:
    """Ghep search string voi base conditions thanh query hoan chinh."""

    # Query hoan chinh = search string + base conditions.
    return f"{search_string} {' '.join(base_conditions)}"


def search_repos(
    query: str,
    sort: str,
    page: int,
    per_page: int,
    max_rate_limit_sleep: int,
) -> tuple[list[dict[str, Any]], int]:
    """Search repo tren GitHub va tra ve items cung total_count cua query."""

    # Goi endpoint search repo va tra ve ca items lan total_count de theo doi do phu query.
    try:
        data = github_get(
            "/search/repositories",
            max_rate_limit_sleep=max_rate_limit_sleep,
            q=query,
            sort=sort,
            order="desc",
            per_page=per_page,
            page=page,
        )
    except SkipRequest as exc:
        print(f"Skip query page: {exc}")
        return [], 0

    return data.get("items", []), int(data.get("total_count", 0))


def build_filter_metadata(
    repo: dict[str, Any],
    search_spec: dict[str, str],
    query: str,
    base_conditions: list[str],
    query_partition: dict[str, Any],
    collected_at: str,
) -> dict[str, Any]:
    """Tao record filter rieng tu mot raw repo item cua GitHub Search."""

    # Tao record rieng cho viec so sanh/loc, khong tron vao raw metadata cua GitHub.
    owner = repo.get("owner") or {}
    license_info = repo.get("license") or {}

    return {
        "repo": repo.get("full_name"),
        "repo_id": repo.get("id"),
        "owner": owner.get("login"),
        "name": repo.get("name"),
        "url": repo.get("html_url"),
        "api_url": repo.get("url"),
        "clone_url": repo.get("clone_url"),
        "git_url": repo.get("git_url"),
        "ssh_url": repo.get("ssh_url"),
        "homepage": repo.get("homepage") or "",
        "description": repo.get("description") or "",
        "topics": repo.get("topics") or [],
        "language": repo.get("language"),
        "license": license_info.get("spdx_id") or license_info.get("key") or "",
        "stars": repo.get("stargazers_count", 0),
        "forks": repo.get("forks_count", 0),
        "watchers": repo.get("watchers_count", 0),
        "open_issues": repo.get("open_issues_count", 0),
        "size_kb": repo.get("size", 0),
        "default_branch": repo.get("default_branch"),
        "created_at": repo.get("created_at"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "archived": bool(repo.get("archived")),
        "fork": bool(repo.get("fork")),
        "disabled": bool(repo.get("disabled")),
        "is_template": bool(repo.get("is_template")),
        "visibility": repo.get("visibility"),
        "source": "github_search",
        "base_conditions": base_conditions,
        "matched_partitions": [query_partition],
        "matched_search_strings": [search_spec["search_string"]],
        "matched_terms": [search_spec["term"]],
        "matched_scopes": [search_spec["scope"]],
        "matched_web_signals": [search_spec["web_signal"]],
        "matched_queries": [query],
        "first_collected_at": collected_at,
        "last_seen_at": collected_at,
    }


def merge_match_metadata(
    existing: dict[str, Any],
    repo: dict[str, Any],
    search_spec: dict[str, str],
    query: str,
    query_partition: dict[str, Any],
    collected_at: str,
) -> bool:
    """Cap nhat filter record khi repo cu xuat hien trong query moi."""

    # Neu repo da ton tai, chi cap nhat cac query/scope match them va metadata moi nhat.
    changed = False

    for field, value in (
        ("matched_search_strings", search_spec["search_string"]),
        ("matched_terms", search_spec["term"]),
        ("matched_scopes", search_spec["scope"]),
        ("matched_web_signals", search_spec["web_signal"]),
        ("matched_queries", query),
    ):
        values = existing.setdefault(field, [])
        if value not in values:
            values.append(value)
            changed = True

    partitions = existing.setdefault("matched_partitions", [])
    if query_partition not in partitions:
        partitions.append(query_partition)
        changed = True

    refresh_fields = {
        "description": repo.get("description") or "",
        "topics": repo.get("topics") or [],
        "stars": repo.get("stargazers_count", 0),
        "forks": repo.get("forks_count", 0),
        "watchers": repo.get("watchers_count", 0),
        "open_issues": repo.get("open_issues_count", 0),
        "size_kb": repo.get("size", 0),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "last_seen_at": collected_at,
    }
    for key, value in refresh_fields.items():
        if existing.get(key) != value:
            existing[key] = value
            changed = True

    return changed


def load_json_list(output_path: Path) -> list[dict[str, Any]]:
    """Doc file JSON list neu da ton tai de ho tro resume."""

    # Cho phep resume: chay lai script se nap file JSON cu va crawl tiep.
    if not output_path.exists():
        return []
    try:
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Neu lan truoc dung dung luc ghi file, file chinh co the rong/hong.
        # Thu recover tu cac file tmp hop le moi nhat truoc khi dung chuong trinh.
        recovered = recover_json_from_tmp(output_path)
        if recovered is None:
            raise SystemExit(f"Existing output is not valid JSON: {output_path}")
        return recovered
    if not isinstance(data, list):
        raise SystemExit(f"Existing output must be a JSON list: {output_path}")
    return data


def recover_json_from_tmp(output_path: Path) -> list[dict[str, Any]] | None:
    """Tim file tmp hop le gan nhat va khoi phuc khi output JSON bi hong."""

    tmp_candidates = sorted(
        list(output_path.parent.glob(f"{output_path.name}*.tmp")),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    for tmp_path in tmp_candidates:
        try:
            data = json.loads(tmp_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, list):
            continue

        backup_path = output_path.with_name(f"{output_path.name}.invalid.bak")
        try:
            output_path.replace(backup_path)
        except OSError:
            pass
        tmp_path.replace(output_path)
        print(f"Recovered {output_path} from {tmp_path}")
        return data

    return None


def write_json(projects: list[dict[str, Any]], output_path: Path) -> None:
    """Ghi JSON an toan bang cach ghi file tam truoc roi replace."""

    # Windows co the khoa file JSON ngan han neu dang mo bang editor/viewer.
    # Vi vay retry replace vai lan thay vi lam chet ca qua trinh crawl.
    payload = json.dumps(projects, ensure_ascii=False, indent=2)
    tmp_path = output_path.with_name(f"{output_path.name}.{os.getpid()}.tmp")
    last_error: PermissionError | None = None

    for attempt in range(1, 8):
        try:
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(output_path)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.25 * attempt)

    try:
        output_path.write_text(payload, encoding="utf-8")
        return
    except PermissionError as exc:
        last_error = exc

    raise PermissionError(
        f"Cannot write {output_path}. Close any app opening this JSON file and rerun."
    ) from last_error


def collect(
    output: str,
    filter_output: str,
    limit: int,
    min_stars: int,
    min_forks: int,
    active_months: int,
    include_backend_terms: bool,
    include_topic_terms: bool,
    split_scopes: bool,
    use_negative_terms: bool,
    sort_modes: list[str],
    max_pages_per_query: int,
    per_page: int,
    max_rate_limit_sleep: int,
    request_delay: float,
) -> list[dict[str, Any]]:
    """Chay toan bo qua trinh crawl metadata va autosave ket qua."""

    # Vong crawl chinh: lap qua sort mode, search string, page va autosave lien tuc.
    output_path = Path(output)
    filter_output_path = Path(filter_output)

    # Nap du lieu cu neu co. Viec nay cho phep script tiep tuc sau khi bi dung giua chung.
    raw_projects = load_json_list(output_path)
    filter_projects = load_json_list(filter_output_path)

    # Tao index trong bo nho de dedupe nhanh theo full_name/owner-name.
    raw_by_repo = {project["full_name"]: project for project in raw_projects if project.get("full_name")}
    raw_index_by_repo = {
        project["full_name"]: index
        for index, project in enumerate(raw_projects)
        if project.get("full_name")
    }
    filter_by_repo = {project["repo"]: project for project in filter_projects if project.get("repo")}

    # Base conditions la phan loc chung khong gay no ket qua: Python, khong fork, khong archived.
    base_conditions = build_base_conditions(
        min_forks=min_forks,
        use_negative_terms=use_negative_terms,
    )
    query_partitions = build_query_partitions(min_stars=min_stars, active_months=active_months)

    # Search specs la phan bien doi: framework/backend/topic + scope can tim.
    # Mac dinh gop readme va description de giam so request GitHub.
    search_specs = build_search_specs(
        include_backend_terms=include_backend_terms,
        include_topic_terms=include_topic_terms,
        split_scopes=split_scopes,
    )
    collected_at = datetime.now(timezone.utc).isoformat()

    print("GitHub metadata crawler")
    print(f"- raw output: {output_path}")
    print(f"- filter output: {filter_output_path}")
    print(f"- loaded existing raw repos: {len(raw_projects)}")
    print(f"- loaded existing filter repos: {len(filter_projects)}")
    print(f"- limit: {limit if limit > 0 else 'no limit'}")
    print(f"- base conditions: {' '.join(base_conditions)}")
    print(f"- query partitions: {len(query_partitions)}")
    print(f"- search strings: {len(search_specs)}")
    print(f"- sort modes: {', '.join(sort_modes)}")
    print(f"- max pages/query: {max_pages_per_query}, per_page: {per_page}")
    print("- autosave: after every new repo or matched-query update")

    page_cap = max_pages_per_query * per_page

    def save_repo(
        repo: dict[str, Any],
        spec: dict[str, str],
        query: str,
        partition: dict[str, Any],
    ) -> bool:
        """Luu mot repo vao raw/filter JSON va tra ve True neu da cham limit."""

        full_name = repo.get("full_name")
        if not full_name:
            return False

        if full_name in raw_by_repo:
            # Raw file luu object GitHub Search gan nhat cho repo do.
            raw_projects[raw_index_by_repo[full_name]] = repo
            raw_by_repo[full_name] = repo
            write_json(raw_projects, output_path)

            # Dedupe theo owner/name nhung van giu lai tat ca query/partition da match.
            if full_name in filter_by_repo:
                changed = merge_match_metadata(
                    existing=filter_by_repo[full_name],
                    repo=repo,
                    search_spec=spec,
                    query=query,
                    query_partition=partition,
                    collected_at=collected_at,
                )
                if changed:
                    write_json(filter_projects, filter_output_path)
            else:
                item = build_filter_metadata(
                    repo=repo,
                    search_spec=spec,
                    query=query,
                    base_conditions=base_conditions,
                    query_partition=partition,
                    collected_at=collected_at,
                )
                filter_projects.append(item)
                filter_by_repo[full_name] = item
                write_json(filter_projects, filter_output_path)
            return limit > 0 and len(raw_projects) >= limit

        # Repo moi: luu raw truoc de khong mat du lieu neu script dung dot ngot.
        raw_projects.append(repo)
        raw_by_repo[full_name] = repo
        raw_index_by_repo[full_name] = len(raw_projects) - 1
        write_json(raw_projects, output_path)

        # Sau khi raw da an toan, tao record filter rieng cho buoc so sanh/loc.
        item = build_filter_metadata(
            repo=repo,
            search_spec=spec,
            query=query,
            base_conditions=base_conditions,
            query_partition=partition,
            collected_at=collected_at,
        )
        filter_projects.append(item)
        filter_by_repo[full_name] = item
        write_json(filter_projects, filter_output_path)

        print(
            f"[{len(raw_projects):04d}] {item['repo']} | "
            f"stars={item['stars']} pushed={item['pushed_at']} | "
            f"matched={spec['search_string']} | "
            f"{partition['pushed_condition']} {partition['star_condition']}"
        )

        return limit > 0 and len(raw_projects) >= limit

    def crawl_partition(
        sort: str,
        spec: dict[str, str],
        partition: dict[str, Any],
        depth: int = 0,
    ) -> bool:
        """Crawl mot partition; neu qua 1000 ket qua thi tu chia nho roi crawl tiep."""

        if limit > 0 and len(raw_projects) >= limit:
            return True

        partition_conditions = base_conditions + partition["conditions"]
        query = build_query(partition_conditions, spec["search_string"])

        print(f"\nSearch sort={sort} page=1: {query}")
        repos, total_count = search_repos(
            query=query,
            sort=sort,
            page=1,
            per_page=per_page,
            max_rate_limit_sleep=max_rate_limit_sleep,
        )
        print(f"GitHub total_count={total_count}, returned={len(repos)}")

        if total_count > page_cap:
            child_partitions = split_partition(partition)
            if child_partitions:
                print(
                    f"Split partition because total_count={total_count} > {page_cap}: "
                    f"{partition['pushed_condition']} {partition['star_condition']}"
                )
                for child in child_partitions:
                    if crawl_partition(sort, spec, child, depth + 1):
                        return True
                return False

            print(
                "Warning: cannot split this partition further; GitHub may expose only "
                f"the first {page_cap} results for this exact query."
            )

        if not repos:
            return False

        for repo in repos:
            if save_repo(repo, spec, query, partition):
                return True

        pages_to_fetch = min(max_pages_per_query, (total_count + per_page - 1) // per_page)
        for page in range(2, pages_to_fetch + 1):
            if limit > 0 and len(raw_projects) >= limit:
                return True

            print(f"\nSearch sort={sort} page={page}: {query}")
            repos, _ = search_repos(
                query=query,
                sort=sort,
                page=page,
                per_page=per_page,
                max_rate_limit_sleep=max_rate_limit_sleep,
            )
            print(f"GitHub returned={len(repos)}")
            if not repos:
                break

            for repo in repos:
                if save_repo(repo, spec, query, partition):
                    return True

            # Delay nhe giua cac page de tranh goi API qua gap.
            time.sleep(request_delay)

        return False

    for sort in sort_modes:
        for spec in search_specs:
            for partition in query_partitions:
                if crawl_partition(sort, spec, partition):
                    write_json(raw_projects, output_path)
                    write_json(filter_projects, filter_output_path)
                    return raw_projects

    write_json(raw_projects, output_path)
    write_json(filter_projects, filter_output_path)
    return raw_projects


def parse_args() -> argparse.Namespace:
    """Khai bao CLI cho crawler."""

    # CLI mac dinh theo yeu cau giai doan 1: crawl het metadata tra ve, stars >= 50, active 12 thang.
    parser = argparse.ArgumentParser(
        description="Crawl GitHub repository metadata for Python web/backend/API candidate projects."
    )
    parser.add_argument(
        "--output",
        default="github_search_raw_repos.json",
        help="Raw GitHub Search repo items. This file keeps the fields returned by GitHub.",
    )
    parser.add_argument(
        "--filter-output",
        default="github_python_web_project_filter.json",
        help="Separate file for match/search/filter metadata used in later comparison.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after N unique repos. Default 0 means no repo limit.",
    )
    parser.add_argument("--min-stars", type=int, default=50)
    parser.add_argument("--min-forks", type=int, default=50)
    parser.add_argument(
        "--active-months",
        type=int,
        default=12,
        help="Only collect repos pushed within the last N months. Use 0 to disable.",
    )
    parser.add_argument(
        "--no-backend-terms",
        action="store_true",
        help="Disable backend/web generic search strings.",
    )
    parser.add_argument(
        "--no-topic-terms",
        action="store_true",
        help="Disable topic:... search strings.",
    )
    parser.add_argument(
        "--split-scopes",
        action="store_true",
        help="Search readme and description separately. Default groups them as in:readme,description.",
    )
    parser.add_argument(
        "--use-negative-terms",
        action="store_true",
        help="Apply negative keywords such as -template, -boilerplate, -cookiecutter.",
    )
    parser.add_argument(
        "--sort",
        nargs="+",
        default=["stars"],
        choices=["stars", "forks", "help-wanted-issues", "updated"],
        help="GitHub search sort modes to run.",
    )
    parser.add_argument(
        "--max-pages-per-query",
        type=int,
        default=10,
        help="GitHub Search exposes up to about 1000 results per query; with per_page=100 this is 10 pages.",
    )
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument(
        "--max-rate-limit-sleep",
        type=int,
        default=60,
        help="Skip a request if GitHub asks to wait longer than this many seconds.",
    )
    parser.add_argument("--request-delay", type=float, default=0.8)
    parser.add_argument(
        "--allow-no-token",
        action="store_true",
        help="Allow anonymous GitHub API calls. Not recommended because it rate-limits quickly.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not GITHUB_TOKEN and not args.allow_no_token:
        raise SystemExit(
            "GITHUB_TOKEN is missing. Set it in this PowerShell terminal first:\n"
            '$env:GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxx"\n'
            "Then run the script again. Use --allow-no-token only if you accept GitHub rate limits."
        )

    collected = collect(
        output=args.output,
        filter_output=args.filter_output,
        limit=args.limit,
        min_stars=args.min_stars,
        min_forks=args.min_forks,
        active_months=args.active_months,
        include_backend_terms=not args.no_backend_terms,
        include_topic_terms=not args.no_topic_terms,
        split_scopes=args.split_scopes,
        use_negative_terms=args.use_negative_terms,
        sort_modes=args.sort,
        max_pages_per_query=args.max_pages_per_query,
        per_page=args.per_page,
        max_rate_limit_sleep=args.max_rate_limit_sleep,
        request_delay=args.request_delay,
    )

    print(f"\nDone. JSON contains {len(collected)} repositories.")
