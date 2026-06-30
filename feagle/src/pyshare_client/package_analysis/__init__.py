__all__ = ["index_package", "index_source"]


def __getattr__(name: str):
    if name in __all__:
        from pyshare_client.package_analysis.service import index_package, index_source

        exports = {
            "index_package": index_package,
            "index_source": index_source,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
