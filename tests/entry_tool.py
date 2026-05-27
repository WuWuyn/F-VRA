# Restore collections ABC aliases removed in Python 3.10 (needed by the
# old `spiral` dependency). Must run before any other import.
import collections
import collections.abc
for _name in ("Iterable", "Mapping", "MutableMapping", "Sequence",
              "MutableSequence", "Set", "MutableSet", "Hashable", "Callable",
              "Container", "Sized", "Iterator", "Generator", "Reversible",
              "Collection"):
    if not hasattr(collections, _name) and hasattr(collections.abc, _name):
        setattr(collections, _name, getattr(collections.abc, _name))

from main.main import main, full_paper_main, full_paper_main_function
import os
# os.environ['CURL_CA_BUNDLE'] = ''
os.environ['TOKENIZERS_PARALLELISM']='false'

if __name__=='__main__':

    full_paper_main_function()

 




