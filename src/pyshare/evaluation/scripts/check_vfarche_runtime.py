"""Offline regression checks for usage, ranking, export and embedding responses."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyshare.evaluation.methods.vfarche.llm import usage, embedding
from pyshare.evaluation.methods.vfarche.ranking import llm_compare
from pyshare.evaluation.metrics.compute_metrics import per_group_scores, load_predictions
from pyshare.evaluation.adapters import vfarche_adapter as adapter
from pyshare.evaluation.adapters.base import RunContext
from pyshare.evaluation.methods.vfarche import cli
from pyshare.evaluation.methods.vfarche.storage import mongo


class RuntimeChecks(unittest.TestCase):
    def test_cve_failure_then_success_and_resume(self):
        rows = [{'cve_id': cid, 'repo_url': 'https://example.invalid/repo',
                 'description': 'test', 'vulnerable_ref': 'ref', 'fixed_funcs': []}
                for cid in ['CVE-BAD', 'CVE-GOOD']]
        saved = {}
        def save(**kwargs):
            saved[kwargs['cve_id']] = kwargs
        with tempfile.TemporaryDirectory() as td, \
             patch('pyshare.evaluation.methods.vfarche.data.load_cve.load', return_value=rows), \
             patch('pyshare.evaluation.methods.vfarche.parser.repo_cloner.clone_or_update', side_effect=[RuntimeError('clone failed'), Path(td)]) as clone, \
             patch('pyshare.evaluation.methods.vfarche.parser.python_parser.parse_repo', return_value=[]), \
             patch('pyshare.evaluation.methods.vfarche.retrieval.select_candidates', return_value=([], 'bm25-fallback')), \
             patch.object(mongo, 'load_topk', side_effect=lambda cid: saved.get(cid)), \
             patch.object(mongo, 'delete_topk'), \
             patch.object(mongo, 'save_topk', side_effect=save):
            args = ['run', '--dataset', 'dummy', '--skip-llm', '--no-cache',
                    '--resume', '--continue-on-error', '--failure-log', str(Path(td) / 'failures.jsonl')]
            self.assertEqual(cli.main(args), 0)
            self.assertEqual(set(saved), {'CVE-GOOD'})
            self.assertEqual(saved['CVE-GOOD']['telemetry']['tokens'], 0)
            self.assertGreaterEqual(saved['CVE-GOOD']['telemetry']['runtime_secs'], 0)
            self.assertEqual(json.loads((Path(td) / 'failures.jsonl').read_text())['cve_id'], 'CVE-BAD')
            rows.pop(0)
            self.assertEqual(cli.main(args), 0)
            self.assertEqual(clone.call_count, 2)  # empty-but-complete checkpoint resumes

    def test_usage_missing_is_not_zero(self):
        usage.reset()
        usage.record({'prompt_tokens': 10, 'completion_tokens': 4})
        usage.record({'total_tokens': 7})
        self.assertEqual(usage.snapshot()['tokens'], 21)
        usage.record(None)
        self.assertIsNone(usage.snapshot()['tokens'])
        self.assertEqual(usage.snapshot()['reported_tokens'], 21)
        usage.reset()
        self.assertEqual(usage.snapshot()['tokens'], 0)

    def test_reverse_pair_cached_winner(self):
        a = {'qualname': 'A', 'name': 'A', 'body': 'def A(): pass', 'file': 'app.py', 'start_line': 1}
        b = {'qualname': 'B', 'name': 'B', 'body': 'def B(): pass', 'file': 'app.py', 'start_line': 2}
        llm_compare._PAIR_CACHE.clear()
        with patch.object(llm_compare, 'chat', return_value='A') as chat:
            self.assertEqual(llm_compare._compare_pair('test', b, a), 0)
            self.assertEqual(llm_compare._compare_pair('test', a, b), 1)
            self.assertEqual(chat.call_count, 1)

    def test_embedding_order_usage_and_denial(self):
        from types import SimpleNamespace
        usage.reset()
        response = SimpleNamespace(status_code=200, text=json.dumps({
            'data': [{'index': 1, 'embedding': [0., 1.]},
                     {'index': 0, 'embedding': [1., 0.]}],
            'usage': {'total_tokens': 3}}))
        with patch.object(embedding, 'EMBEDDING_API_KEY', 'test'), \
             patch.object(embedding.requests, 'post', return_value=response) as post:
            self.assertEqual(embedding.embed_batch(['a', 'b']), [[1., 0.], [0., 1.]])
            self.assertEqual(usage.snapshot()['tokens'], 3)
            response.status_code = 403
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                embedding.embed_batch(['a'])
            self.assertEqual(post.call_count, 2)  # no retry for permanent denial

    def test_export_preserves_telemetry_and_class_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            master = root / 'master.jsonl'
            master.write_text(json.dumps({'advisory_id': 'CVE-X', 'group_id': 'g',
                'root_cause_functions': [{'file_path': 'app.py',
                    'qualified_name': 'app.Right.save', 'function_name': 'save'}]}) + '\n')
            ctx = RunContext(master_path=master, out_dir=root, python_bin=sys.executable)
            def export(cmd, **kwargs):
                Path(cmd[-1]).write_text(json.dumps({'CVE-X': {
                    'topk': [{'file': 'app.py', 'name': 'save', 'qualname': 'Wrong.save'},
                             {'file': 'app.py', 'name': 'save', 'qualname': 'Right.save'}],
                    'telemetry': {'tokens': 42, 'runtime_secs': 2.5}}}))
            with patch.object(adapter, 'run_step', side_effect=export):
                records = adapter.VFArcheAdapter()._export_and_normalize(
                    [{'cve_id': 'CVE-X'}], ['CVE-X'], 'pairwise', ctx)
            self.assertEqual(records[0]['tokens'], 42)
            self.assertEqual(records[0]['runtime_secs'], 2.5)
            scores = per_group_scores(records, [1, 5])[0]
            self.assertEqual(scores['hit@1'], 0)
            self.assertEqual(scores['rr'], 0.5)
            self.assertEqual(scores['weak_hit'], 0)
            (root / 'vfarche.jsonl').write_text(json.dumps(records[0]) + '\n')
            master.unlink()
            (root / 'vfarche_failures.jsonl').write_text('{"error": "test"}\n')
            self.assertEqual(len(load_predictions(root)), 1)


if __name__ == '__main__':
    unittest.main()
