from pathlib import Path

from typer.testing import CliRunner

from pyshare.cli.main import app
from pyshare.localization.candidates import select_patch_absent
from pyshare.localization.embedding import OpenRouterEmbeddingBackend
from pyshare.localization.function_parser import parse_repo
from pyshare.localization.function_parser import parse_repository
from pyshare.localization.metadata import ResolvedMetadata, download_patch
from pyshare.localization.models import LocalizationRequest
from pyshare.localization.repo_resolver import github_repo_url_from_reference
from pyshare.localization.service import localize, localize_vulnerable_functions

runner = CliRunner()


def test_parse_repo_extracts_python_functions():
    funcs = parse_repo("tests/fixtures/sample_app")

    qualnames = {func["qualname"] for func in funcs}

    assert {"main", "public_api", "unused_api", "Client.fetch"} <= qualnames


def test_localize_ranks_candidate_functions_with_fallback_retrieval():
    result = localize(
        "CVE-X",
        description="request fetch url using requests get",
        repo_path="tests/fixtures/sample_app",
        top_k=3,
    )

    assert result.mode == "PATCH_ABSENT"
    assert result.vf == "Client.fetch"
    assert "Client.fetch" in result.candidates


def test_hybrid_retrieval_uses_embedding_signal(monkeypatch):
    functions = parse_repository("tests/fixtures/sample_app")
    fetch_id = next(item.identity for item in functions if item.qualname == "Client.fetch")

    monkeypatch.setattr(
        "pyshare.localization.candidates.lexical_scores",
        lambda description, items: {item.identity: 0.0 for item in items},
    )
    monkeypatch.setattr(
        "pyshare.localization.candidates.embedding_scores",
        lambda description, items: (
            {
                item.identity: 0.95 if item.identity == fetch_id else 0.05
                for item in items
            },
            "test-light-model",
        ),
    )

    selection = select_patch_absent(
        "credentials escape across a redirected secure connection",
        functions,
        pool_size=4,
        use_embeddings=True,
    )

    assert selection.candidates[0].qualname == "Client.fetch"
    assert selection.embedding_model == "test-light-model"
    assert selection.embedding_status == "used"
    assert selection.relevance_scores[fetch_id] == 1.0
    assert selection.relevance_scores[fetch_id] > selection.relevance_scores[
        next(item.identity for item in functions if item.qualname == "main")
    ]


def test_embedding_failure_falls_back_to_bm25(monkeypatch):
    functions = parse_repository("tests/fixtures/sample_app")

    def fail_embedding(description, items):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(
        "pyshare.localization.candidates.embedding_scores",
        fail_embedding,
    )

    selection = select_patch_absent(
        "request fetch url using requests get",
        functions,
        use_embeddings=True,
    )

    assert selection.candidates[0].qualname == "Client.fetch"
    assert selection.embedding_scores == {}
    assert selection.embedding_status == "fallback: model unavailable"


def test_openrouter_embedding_backend_batches_and_orders_vectors(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]},
                ]
            }

    monkeypatch.setattr(
        "pyshare.localization.embedding.settings.openrouter_api_key",
        "test-key",
    )

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("pyshare.localization.embedding.requests.post", fake_post)

    backend = OpenRouterEmbeddingBackend("qwen/qwen3-embedding-0.6b")
    vectors = backend.embed(["query", "function"])

    assert vectors == [[1.0, 0.0], [0.0, 1.0]]
    assert captured["url"] == "https://openrouter.ai/api/v1/embeddings"
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["json"]["input"] == ["query", "function"]
    assert captured["json"]["model"] == "qwen/qwen3-embedding-0.6b"


def test_patch_absent_report_has_product_schema():
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="HTTP request can hang without a timeout",
            cwe_id="CWE-400",
            repository_path=Path("tests/fixtures/sample_app"),
            top_k=3,
        )
    )

    data = report.to_dict()
    assert data["mode"] == "PATCH_ABSENT"
    assert data["metadata_source"] == "manual"
    assert data["patch_source"] is None
    assert len(data["candidates"]) == 3
    assert {
        "rank",
        "score",
        "confidence",
        "function_name",
        "qualname",
        "file_path",
        "start_line",
        "end_line",
        "source_excerpt",
        "why_this_may_be_vulnerable",
        "evidence_used",
    } <= data["candidates"][0].keys()


def test_patch_present_tracks_modified_function_and_callers():
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="HTTP request can hang without a timeout",
            repository_path=Path("tests/fixtures/sample_app"),
            patch_path=Path("tests/fixtures/sample_app/fix.patch"),
            top_k=5,
        )
    )

    by_name = {candidate.qualname: candidate for candidate in report.candidates}
    assert report.mode == "PATCH_PRESENT"
    assert report.patch_source is not None
    assert "Client.fetch" in by_name
    assert any("changed patch lines" in item for item in by_name["Client.fetch"].evidence_used)
    assert "public_api" in by_name
    assert any("patch-related function" in item for item in by_name["public_api"].evidence_used)


def test_auto_resolve_falls_back_to_patch_absent(monkeypatch):
    monkeypatch.setattr(
        "pyshare.localization.service.resolve_metadata",
        lambda cve_id: ResolvedMetadata(
            cve_id=cve_id,
            description="unsafe HTTP request handling",
            source="OSV",
        ),
    )

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            repository_path=Path("tests/fixtures/sample_app"),
            auto_resolve_patch=True,
            top_k=2,
        )
    )

    assert report.mode == "PATCH_ABSENT"
    assert report.metadata_source == "OSV"


def test_auto_clone_inferred_github_repository_when_repository_missing(monkeypatch):
    cloned = {}

    monkeypatch.setattr(
        "pyshare.localization.service.resolve_metadata",
        lambda cve_id: ResolvedMetadata(
            cve_id=cve_id,
            description="unsafe HTTP request handling",
            references=["https://github.com/example/sample_app/commit/abc123"],
            patch_urls=[],
            source="OSV",
        ),
    )

    def fake_clone(repo_url):
        cloned["repo_url"] = repo_url
        return Path("tests/fixtures/sample_app")

    monkeypatch.setattr("pyshare.localization.service.clone_or_update", fake_clone)

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            repository_path=Path("tests/fixtures/not_cloned_yet"),
            top_k=2,
            use_embeddings=False,
        )
    )

    assert cloned["repo_url"] == "https://github.com/example/sample_app.git"
    assert report.mode == "PATCH_ABSENT"
    assert report.metadata["repository_source"] == "https://github.com/example/sample_app.git"
    assert report.repository_path.endswith("tests\\fixtures\\sample_app") or report.repository_path.endswith(
        "tests/fixtures/sample_app"
    )


def test_openrouter_rerank_model_is_separate_from_chat_model(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "results": [
                    {"index": 0, "relevance_score": 0.91},
                    {"index": 1, "relevance_score": 0.25},
                ]
            }

    monkeypatch.setattr("pyshare.localization.llm_client.settings.openrouter_api_key", "test-key")
    monkeypatch.setattr("pyshare.localization.ranking.settings.openrouter_api_key", "test-key")
    monkeypatch.setattr(
        "pyshare.localization.ranking.settings.openrouter_rerank_model",
        "nvidia/llama-nemotron-rerank-vl-1b-v2:free",
    )

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("pyshare.localization.llm_client.requests.post", fake_post)

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id="CVE-X",
            cve_description="request fetch url using requests get",
            repository_path=Path("tests/fixtures/sample_app"),
            top_k=2,
            use_embeddings=False,
        )
    )

    assert captured["url"] == "https://openrouter.ai/api/v1/rerank"
    assert captured["json"]["model"] == "nvidia/llama-nemotron-rerank-vl-1b-v2:free"
    assert captured["json"]["query"].startswith("request fetch url")
    assert captured["json"]["top_n"] == len(captured["json"]["documents"])
    assert report.metadata["rerank_used"] is True
    assert report.metadata["rerank_source"] == "openrouter_rerank"
    assert "llm_used" not in report.metadata


def test_github_repo_url_from_reference_normalizes_commit_url():
    assert (
        github_repo_url_from_reference("https://github.com/psf/requests/commit/abc123")
        == "https://github.com/psf/requests.git"
    )


def test_download_patch_uses_github_patch_endpoint(monkeypatch):
    requested_urls = []

    class Response:
        status_code = 200
        text = "@@ -1 +1 @@\n-old\n+new\n"

    def fake_get(url, **kwargs):
        requested_urls.append(url)
        return Response()

    monkeypatch.setattr("pyshare.localization.metadata.requests.get", fake_get)

    downloaded = download_patch("https://github.com/example/project/commit/abc123")

    assert downloaded is not None
    assert downloaded[1].endswith("/commit/abc123.patch")
    assert requested_urls == ["https://github.com/example/project/commit/abc123.patch"]


def test_localization_parse_diagnostic_runs():
    result = runner.invoke(
        app,
        [
            "localization",
            "parse",
            "--repository",
            "tests/fixtures/sample_app",
            "--limit",
            "2",
        ],
    )

    assert result.exit_code == 0
    assert '"functions_found": 4' in result.stdout
    assert '"qualname": "main"' in result.stdout


def test_localization_patch_and_tracker_diagnostics_run():
    patch_result = runner.invoke(
        app,
        [
            "localization",
            "patch",
            "--patch",
            "tests/fixtures/sample_app/fix.patch",
        ],
    )
    tracker_result = runner.invoke(
        app,
        [
            "localization",
            "track",
            "--repository",
            "tests/fixtures/sample_app",
            "--patch",
            "tests/fixtures/sample_app/fix.patch",
        ],
    )

    assert patch_result.exit_code == 0
    assert '"status": "ok"' in patch_result.stdout
    assert '"file_path": "pkg/lib.py"' in patch_result.stdout
    assert tracker_result.exit_code == 0
    assert '"qualname": "Client.fetch"' in tracker_result.stdout
    assert '"qualname": "public_api"' in tracker_result.stdout
