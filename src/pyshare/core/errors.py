class PyShareError(Exception):
    pass

class IndexNotFound(PyShareError):
    pass

class CVENotLocalized(PyShareError):
    pass

class GraphConnectionError(PyShareError):
    pass
