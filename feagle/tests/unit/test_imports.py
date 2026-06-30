def test_split_packages_import():
    import importlib.util

    import pyshare_core
    import pyshare_client
    import pyshare_server
    from pyshare_client.cli import app as client_app
    from pyshare_server.localization.service import localize
    from pyshare_server.cli import app as server_app

    assert pyshare_core is not None
    assert pyshare_client is not None
    assert pyshare_server is not None
    assert client_app is not None
    assert localize is not None
    assert server_app is not None
    assert importlib.util.find_spec("pyshare") is None


def test_client_cli_import_does_not_load_server_package():
    import sys

    sys.modules.pop("pyshare_server", None)
    import pyshare_client.cli

    assert "pyshare_server" not in sys.modules
