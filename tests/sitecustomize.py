"""
Auto-loaded by Python at interpreter startup (found on sys.path).

Restores the ``collections`` ABC aliases that were removed in Python 3.10.
Older dependencies such as ``spiral`` still reference ``collections.Iterable``
instead of ``collections.abc.Iterable``.
"""
import collections
import collections.abc

_ABC_NAMES = (
    "Iterable", "Mapping", "MutableMapping", "Sequence", "MutableSequence",
    "Set", "MutableSet", "Hashable", "Callable", "Container", "Sized",
    "Iterator", "Generator", "Reversible", "Collection", "Awaitable",
    "Coroutine", "AsyncIterable", "AsyncIterator", "ByteString",
)

for _name in _ABC_NAMES:
    if not hasattr(collections, _name) and hasattr(collections.abc, _name):
        setattr(collections, _name, getattr(collections.abc, _name))
