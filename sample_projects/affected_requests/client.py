"""Sample project — HTTP client built on requests.

Demonstrates a typical pattern that uses the vulnerable
``requests.sessions.Session.request`` method (via ``session.get()`` /
``session.post()``). PyShare's AST direct-caller scan will pick up
``request`` calls via the Session API.

Expected PyShare verdict for CVE-2024-35195 (vf = requests.sessions.Session.request):
    AFFECTED via client.fetch / client.post_json
"""
import requests


def make_session(token):
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    return s


def fetch(url, token=""):
    """Direct call to the vulnerable Session.request entry point."""
    s = make_session(token)
    return s.request("GET", url)   # <-- direct call to Session.request


def post_json(url, payload, token=""):
    """Same path via a different verb."""
    s = make_session(token)
    return s.request("POST", url, json=payload)


def fetch_default(url):
    """Top-level convenience using the module-level session.

    requests.get internally calls Session.request, but our static
    scanner won't follow that bridge — this is documented behaviour.
    """
    return requests.get(url)


def main():
    print(fetch("https://example.com").status_code)


if __name__ == "__main__":
    main()
