"""P-ICL pattern embedding - faithful VFFinder Section 4.1.2 port.

The paper's P-ICL selects demonstrations by grammatical pattern, not raw
vocabulary:

  STEP 1  Anchor entity recognition - replace VPV / vulnerability type /
          component / attacker spans with anchor tokens. That is done in
          `case_pool.anchor_abstract`.
  STEP 2  Parsing tree construction - constituency parse of the abstracted
          sentence (paper: Stanford parser; here: benepar, the standard Python
          constituency parser) plus the paper's two pruning heuristics.
  STEP 3  Pattern retrieval - concatenate the pruned tree's leaf nodes into a
          sequence, embed that sequence with an autoencoder, and rank pool cases
          by cosine.

The authors' released source references a trained tree-sequence autoencoder but
does not ship the model artifact. To keep the paper mechanism instead of falling
back to lexical TF-IDF/LSA, `PatternEmbedder` trains a small GRU sequence
autoencoder on the case-pool pattern sequences and uses the encoder bottleneck
as the pattern vector.
"""

from __future__ import annotations

from collections import Counter
from importlib import metadata

import numpy as np

# Anchor tokens emitted by case_pool.anchor_abstract(). These survive pruning
# (paper STEP 2: delete all leaf nodes except anchor nodes and phrase nodes).
ANCHOR_TOKENS = frozenset({
    "PRODUCT", "COMPONENT", "VTYPE", "ATTACKER", "VERSION", "VPV", "VT",
})


# ---------------------------------------------------------------------------
# Tree pruning + pattern extraction  (paper STEP 2)
# ---------------------------------------------------------------------------

def _is_preterminal(node) -> bool:
    """A POS-tag node: a Tree with one string child, e.g. (NN token)."""
    from nltk.tree import Tree
    return isinstance(node, Tree) and len(node) == 1 and isinstance(node[0], str)


def _is_phrase(node) -> bool:
    """A phrase/clause node (NP, VP, PP, S, ...), not a POS preterminal."""
    from nltk.tree import Tree
    return isinstance(node, Tree) and not _is_preterminal(node)


def _contains_phrase(node) -> bool:
    """True when a direct child is itself a phrase node."""
    return any(_is_phrase(c) for c in node)


def pattern_tokens(node) -> list[str]:
    """Return the paper-style pruned-tree leaf sequence.

    Applies the paper's two heuristics in one pass:
      H1  A lowest-level phrase with no nested phrase collapses to its label,
          unless it carries anchor tokens.
      H2  Ordinary word leaves are dropped; anchor tokens and phrase labels
          remain in the sequence.
    """
    if isinstance(node, str):
        return [node] if node in ANCHOR_TOKENS else []
    if _is_preterminal(node):
        word = node[0]
        return [word] if word in ANCHOR_TOKENS else []
    if not _contains_phrase(node):
        anchors = [w for w in node.leaves() if w in ANCHOR_TOKENS]
        return anchors if anchors else [node.label()]
    out: list[str] = []
    for child in node:
        out.extend(pattern_tokens(child))
    return out


def _shim_t5_tokenizer_for_transformers5() -> None:
    """transformers 5 dropped the slow-tokenizer `build_inputs_with_special_tokens`
    method that benepar 0.2.0 still calls, so benepar_en3 crashes on load. Restore
    the standard T5 implementation (append EOS). Env-compat shim only: it does NOT
    change the parse - verified the trees are identical. Idempotent (no-op once
    benepar ships transformers-5 support, or if we pin transformers<5)."""
    try:
        from transformers import T5Tokenizer
    except Exception:  # noqa: BLE001 - transformers layout changed; nothing to patch
        return
    if hasattr(T5Tokenizer, "build_inputs_with_special_tokens"):
        return

    def _build(self, token_ids_0, token_ids_1=None):
        eos = [self.eos_token_id]
        if token_ids_1 is None:
            return token_ids_0 + eos
        return token_ids_0 + eos + token_ids_1 + eos

    T5Tokenizer.build_inputs_with_special_tokens = _build


class ConstituencyParser:
    """Lazy benepar constituency parser over spaCy.

    benepar is the Python stand-in for the paper's Stanford parser. Loading is
    lazy so importing this module never forces the heavy model.
    """

    def __init__(self, spacy_model: str = "en_core_web_sm",
                 benepar_model: str = "benepar_en3"):
        import spacy
        import benepar  # noqa: F401  (registers the spaCy pipe)
        self.spacy_model = spacy_model
        self.benepar_model = benepar_model
        try:
            benepar_version = metadata.version("benepar")
        except metadata.PackageNotFoundError:
            benepar_version = None
        self.stats = {
            "spacy_model": spacy_model,
            "benepar_model": benepar_model,
            "spacy_version": getattr(spacy, "__version__", None),
            "benepar_version": benepar_version,
            "texts_seen": 0,
            "empty_texts": 0,
            "sentences_seen": 0,
            "parse_success": 0,
            "parse_empty": 0,
            "parse_failures": 0,
        }
        try:
            self.nlp = spacy.load(spacy_model, disable=["ner", "lemmatizer"])
        except OSError as exc:
            raise OSError(
                f"spaCy model '{spacy_model}' missing - run "
                f"`python -m spacy download {spacy_model}`"
            ) from exc
        if "benepar" not in self.nlp.pipe_names:
            _shim_t5_tokenizer_for_transformers5()
            try:
                self.nlp.add_pipe("benepar", config={"model": benepar_model})
            except Exception as exc:  # noqa: BLE001
                raise OSError(
                    f"benepar failed to load model '{benepar_model}': "
                    f"{type(exc).__name__}: {exc}. If the model is missing, run "
                    f"`python -c \"import benepar; benepar.download('{benepar_model}')\"`"
                ) from exc

    def pattern(self, text: str) -> list[str]:
        """Anchor-abstracted text -> concatenated pruned-tree leaf sequence."""
        from nltk.tree import Tree
        self.stats["texts_seen"] += 1
        if not text or not text.strip():
            self.stats["empty_texts"] += 1
            return []
        doc = self.nlp(text)
        seq: list[str] = []
        for sent in doc.sents:
            self.stats["sentences_seen"] += 1
            try:
                parse = sent._.parse_string
            except Exception:
                self.stats["parse_failures"] += 1
                raise
            if parse:
                self.stats["parse_success"] += 1
                seq.extend(pattern_tokens(Tree.fromstring(parse)))
            else:
                self.stats["parse_empty"] += 1
        return seq


# ---------------------------------------------------------------------------
# Pattern embedding  (paper STEP 3 - "autoencoder")
# ---------------------------------------------------------------------------

_PAD = 0
_BOS = 1
_EOS = 2
_UNK = 3
_SPECIALS = {"<pad>": _PAD, "<bos>": _BOS, "<eos>": _EOS, "<unk>": _UNK}


class PatternEmbedder:
    """Embed pattern-token sequences via a neural sequence autoencoder."""

    def __init__(self,
                 n_components: int = 128,
                 *,
                 token_dim: int = 64,
                 hidden_dim: int = 128,
                 epochs: int = 80,
                 batch_size: int = 32,
                 learning_rate: float = 1e-3,
                 max_len: int = 96,
                 seed: int = 0):
        self.n_components = n_components
        self.token_dim = token_dim
        self.hidden_dim = hidden_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.max_len = max_len
        self.seed = seed
        self._vocab: dict[str, int] = dict(_SPECIALS)
        self._model = None
        self._device = None
        self.stats = {
            "n_components": n_components,
            "token_dim": token_dim,
            "hidden_dim": hidden_dim,
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "max_len": max_len,
            "seed": seed,
            "fit_pool_size": 0,
            "vocab_size": len(self._vocab),
            "device": None,
            "embedded_patterns": 0,
        }

    def _require_torch(self):
        try:
            import torch
            import torch.nn as nn
        except ImportError as exc:
            raise ImportError(
                "P-ICL pattern embedding requires torch for the neural sequence "
                "autoencoder. Install configs/evaluation/requirements/vffinder.txt."
            ) from exc
        return torch, nn

    def _build_vocab(self, pattern_seqs: list[list[str]]) -> None:
        counter = Counter(t for seq in pattern_seqs for t in seq)
        self._vocab = dict(_SPECIALS)
        for token, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
            if token not in self._vocab:
                self._vocab[token] = len(self._vocab)

    def _ids(self, seq: list[str]) -> list[int]:
        body = [self._vocab.get(t, _UNK) for t in seq[: self.max_len - 1]]
        return body if body else [_UNK]

    def _tensorize(self, pattern_seqs: list[list[str]]):
        torch, _ = self._require_torch()
        ids = [self._ids(seq) for seq in pattern_seqs]
        width = min(self.max_len, max(len(x) for x in ids) + 1)
        enc = torch.full((len(ids), width), _PAD, dtype=torch.long)
        dec = torch.full((len(ids), width), _PAD, dtype=torch.long)
        target = torch.full((len(ids), width), _PAD, dtype=torch.long)
        lengths = torch.zeros(len(ids), dtype=torch.long)
        for i, seq_ids in enumerate(ids):
            body = seq_ids[: width - 1]
            enc_row = body + [_EOS]
            dec_row = [_BOS] + body
            target_row = body + [_EOS]
            enc[i, :len(enc_row)] = torch.tensor(enc_row)
            dec[i, :len(dec_row)] = torch.tensor(dec_row)
            target[i, :len(target_row)] = torch.tensor(target_row)
            lengths[i] = len(enc_row)
        return enc, dec, target, lengths

    def _new_model(self, vocab_size: int):
        torch, nn = self._require_torch()

        class _SeqAutoencoder(nn.Module):
            def __init__(self, vocab: int, token_dim: int, hidden_dim: int,
                         latent_dim: int):
                super().__init__()
                self.embedding = nn.Embedding(vocab, token_dim, padding_idx=_PAD)
                self.encoder = nn.GRU(
                    token_dim, hidden_dim, batch_first=True, bidirectional=True)
                self.to_latent = nn.Linear(hidden_dim * 2, latent_dim)
                self.from_latent = nn.Linear(latent_dim, hidden_dim)
                self.decoder = nn.GRU(token_dim, hidden_dim, batch_first=True)
                self.output = nn.Linear(hidden_dim, vocab)

            def encode(self, enc, lengths):
                emb = self.embedding(enc)
                packed = nn.utils.rnn.pack_padded_sequence(
                    emb, lengths.cpu(), batch_first=True, enforce_sorted=False)
                _, hidden = self.encoder(packed)
                h = torch.cat([hidden[-2], hidden[-1]], dim=1)
                return self.to_latent(h)

            def forward(self, enc, lengths, dec):
                latent = self.encode(enc, lengths)
                h0 = torch.tanh(self.from_latent(latent)).unsqueeze(0)
                dec_emb = self.embedding(dec)
                out, _ = self.decoder(dec_emb, h0)
                return self.output(out), latent

        return _SeqAutoencoder(
            vocab_size, self.token_dim, self.hidden_dim, self.n_components)

    def fit(self, pattern_seqs: list[list[str]]) -> "PatternEmbedder":
        self.stats["fit_pool_size"] = len(pattern_seqs)
        if not pattern_seqs:
            self._model = None
            return self
        torch, nn = self._require_torch()
        torch.manual_seed(self.seed)
        self._build_vocab(pattern_seqs)
        enc, dec, target, lengths = self._tensorize(pattern_seqs)
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.stats["vocab_size"] = len(self._vocab)
        self.stats["device"] = str(self._device)
        self._model = self._new_model(len(self._vocab)).to(self._device)
        opt = torch.optim.Adam(self._model.parameters(), lr=self.learning_rate)
        loss_fn = nn.CrossEntropyLoss(ignore_index=_PAD)
        generator = torch.Generator().manual_seed(self.seed)

        n = enc.shape[0]
        for _ in range(self.epochs):
            order = torch.randperm(n, generator=generator)
            for start in range(0, n, self.batch_size):
                idx = order[start:start + self.batch_size]
                b_enc = enc[idx].to(self._device)
                b_dec = dec[idx].to(self._device)
                b_target = target[idx].to(self._device)
                b_lengths = lengths[idx].to(self._device)
                logits, _ = self._model(b_enc, b_lengths, b_dec)
                loss = loss_fn(logits.reshape(-1, logits.shape[-1]),
                               b_target.reshape(-1))
                opt.zero_grad()
                loss.backward()
                opt.step()
        return self

    def embed(self, pattern_seqs: list[list[str]]) -> np.ndarray:
        self.stats["embedded_patterns"] += len(pattern_seqs)
        if not pattern_seqs:
            return np.zeros((0, self.n_components), dtype="float32")
        if self._model is None:
            return np.zeros((len(pattern_seqs), self.n_components), dtype="float32")
        if self._device is None:
            raise RuntimeError("PatternEmbedder.embed called before fit")
        enc, _, _, lengths = self._tensorize(pattern_seqs)
        self._model.eval()
        with self._require_torch()[0].no_grad():
            z = self._model.encode(
                enc.to(self._device), lengths.to(self._device)).cpu().numpy()
        norms = np.linalg.norm(z, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return (z / norms).astype("float32")


# ---------------------------------------------------------------------------
# Self-check - runs without benepar (mocks the parse with literal trees).
#   python -m pyshare.evaluation.methods.vffinder.extraction.pattern_embed
# ---------------------------------------------------------------------------

def _demo() -> None:
    from nltk.tree import Tree

    # H1: a lowest phrase with no anchor collapses to its label.
    t1 = Tree.fromstring("(NP (DT the) (NN attack))")
    assert pattern_tokens(t1) == ["NP"], pattern_tokens(t1)

    # Anchor leaf survives the collapse.
    t2 = Tree.fromstring("(NP (NNP VPV))")
    assert pattern_tokens(t2) == ["VPV"], pattern_tokens(t2)

    # Nested phrases: recurse; collapse leaf phrases and keep anchors in order.
    tree = Tree.fromstring(
        "(S (NP (NNP VPV)) (VP (VBZ is) (ADJP (JJ vulnerable)) "
        "(PP (TO to) (NP (NNP VT))) (PP (IN via) (NP (NN attack)))))")
    pat = pattern_tokens(tree)
    assert pat[0] == "VPV" and "VT" in pat, pat
    assert pat.count("VPV") == 1

    # Embedder: an identical pattern should rank above dissimilar patterns.
    pool = [
        ["VPV", "VP", "VT", "NP"],
        ["NP", "VP", "NP"],
        ["ATTACKER", "VP", "COMPONENT"],
    ]
    emb = PatternEmbedder(
        n_components=8, hidden_dim=16, token_dim=8, epochs=20, batch_size=2
    ).fit(pool)
    mat = emb.embed(pool)
    query = emb.embed([["VPV", "VP", "VT", "NP"]])[0]
    sims = mat @ query
    assert int(np.argmax(sims)) == 0, sims
    print("pattern_embed self-check OK:", pat)


if __name__ == "__main__":
    _demo()
