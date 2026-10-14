"""Offline regression tests for publishing the SNI domain list."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "fetch_sni_domains", Path(__file__).with_name("fetch-sni-domains.py")
)
fetcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetcher)


class DomainOutputTests(unittest.TestCase):
    def setUp(self):
        # Keep generated test files inside the tracked workspace.
        scratch = Path(__file__).resolve().parent.parent / "target" / "test-tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "sni.txt"
        self.output.write_text("old.example.com\n", encoding="utf-8")

    def test_empty_result_preserves_existing_file(self):
        with self.assertRaisesRegex(ValueError, "existing output has been preserved"):
            fetcher.write_domain_list(str(self.output), [])
        self.assertEqual(self.output.read_text(), "old.example.com\n")

    def test_failed_replace_preserves_existing_file_and_removes_temporary_file(self):
        with mock.patch.object(fetcher.os, "replace", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                fetcher.write_domain_list(str(self.output), ["new.example.com"])
        self.assertEqual(self.output.read_text(), "old.example.com\n")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    def test_success_replaces_complete_list_and_preserves_permissions(self):
        self.output.chmod(0o640)
        fetcher.write_domain_list(str(self.output), ["one.example.com", "two.example.com"])
        self.assertEqual(self.output.read_text(), "one.example.com\ntwo.example.com\n")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o640)

    def run_offline_fetcher(self, *, candidates, tls_compatible=False, sources_only=False):
        argv = ["--output", str(self.output), "--threads", "1", "--skip-china-filter", "--skip-semantic-filter"]
        if sources_only:
            argv.append("--sources-only")
        with (
            mock.patch.object(fetcher, "get_server_region", return_value="unknown"),
            mock.patch.object(fetcher, "get_known_good_by_region", return_value=candidates),
            mock.patch.object(fetcher, "load_extra_domains", return_value=set()),
            mock.patch.object(fetcher, "fetch_v2ray_geosite_categories", return_value=(set(), 0)),
            mock.patch.object(fetcher, "fetch_extra_sources", return_value=(set(), 0)),
            mock.patch.object(fetcher, "test_domain_openssl", side_effect=lambda domain: (domain, tls_compatible)),
            mock.patch.dict(os.environ, {}, clear=True),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return fetcher.run(argv)

    def test_all_tls_checks_fail_returns_nonzero_and_preserves_list(self):
        self.assertEqual(self.run_offline_fetcher(candidates=["www.example.com"]), 1)
        self.assertEqual(self.output.read_text(), "old.example.com\n")

    def test_empty_sources_returns_nonzero_and_preserves_list(self):
        self.assertEqual(self.run_offline_fetcher(candidates=[], sources_only=True), 1)
        self.assertEqual(self.output.read_text(), "old.example.com\n")

    def test_successful_tls_check_publishes_list(self):
        self.assertEqual(self.run_offline_fetcher(candidates=["www.example.com"], tls_compatible=True), 0)
        self.assertEqual(self.output.read_text(), "www.example.com\n")


if __name__ == "__main__":
    unittest.main()
