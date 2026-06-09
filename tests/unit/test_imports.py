def test_pyshare_imports():
    import pyshare
    from pyshare.cli.main import app
    from pyshare.localization.service import localize

    assert pyshare is not None
    assert app is not None
    assert localize is not None
