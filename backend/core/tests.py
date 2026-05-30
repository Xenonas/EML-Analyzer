import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from analysis.utils import get_sha256
from config.settings import load_env_file

from .authentication import extract_authentication_statuses
from .email_authentication import verify_email_authentication
from .forms import UploadFileForm
from .lookup import _fetch_rdap, _virustotal_url_id, lookup_indicator
from .models import UploadedSample
from .risk_scoring import score_risk
from .tasks import analyze_uploaded_sample
from .url_analysis import analyze_urls


class HeaderExtractionTests(TestCase):
    def test_reply_to_falls_back_to_in_reply_to(self):
        eml = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Test\r\n"
            b"In-Reply-To: <thread-123@example.com>\r\n"
            b"\r\n"
            b"Body"
        )

        sample = UploadedSample.objects.create(
            file=SimpleUploadedFile("sample.eml", eml, content_type="message/rfc822"),
            original_name="sample.eml",
            sha256="",
            status="queued",
        )

        analyze_uploaded_sample(sample.id)
        sample.refresh_from_db()

        self.assertEqual(sample.analysisresult.header_reply_to, "<thread-123@example.com>")

    def test_user_agent_falls_back_to_x_user_agent(self):
        eml = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Test\r\n"
            b"X-User-Agent: Mobile Mail 2.0\r\n"
            b"\r\n"
            b"Body"
        )

        sample = UploadedSample.objects.create(
            file=SimpleUploadedFile("sample.eml", eml, content_type="message/rfc822"),
            original_name="sample.eml",
            sha256="",
            status="queued",
        )

        analyze_uploaded_sample(sample.id)
        sample.refresh_from_db()

        self.assertEqual(sample.analysisresult.header_user_agent, "Mobile Mail 2.0")

    def test_extracts_plain_text_body(self):
        eml = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Body Test\r\n"
            b"\r\n"
            b"Line one\r\nLine two"
        )

        sample = UploadedSample.objects.create(
            file=SimpleUploadedFile("sample.eml", eml, content_type="message/rfc822"),
            original_name="sample.eml",
            sha256="",
            status="queued",
        )

        analyze_uploaded_sample(sample.id)
        sample.refresh_from_db()

        self.assertEqual(sample.analysisresult.body_text, "Line one\nLine two")

    def test_extracts_attachment_metadata_and_flags_risky_extensions(self):
        eml = (
            b"From: sender@example.com\r\n"
            b"To: receiver@example.com\r\n"
            b"Subject: Attachment Test\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
            b"\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Body\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: application/octet-stream; name=\"invoice.exe\"\r\n"
            b"Content-Disposition: attachment; filename=\"invoice.exe\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"QUJD\r\n"
            b"--BOUNDARY--\r\n"
        )

        sample = UploadedSample.objects.create(
            file=SimpleUploadedFile("sample.eml", eml, content_type="message/rfc822"),
            original_name="sample.eml",
            sha256="",
            status="queued",
        )

        analyze_uploaded_sample(sample.id)
        sample.refresh_from_db()

        attachment = sample.analysisresult.attachments[0]
        self.assertEqual(attachment["filename"], "invoice.exe")
        self.assertEqual(attachment["size"], 3)
        self.assertTrue(attachment["risky"])
        self.assertEqual(attachment["risk"], "risky_extension")


class UploadHelperTests(TestCase):
    def test_get_sha256_preserves_file_position(self):
        uploaded_file = SimpleUploadedFile("sample.eml", b"abcdef")
        uploaded_file.seek(3)

        digest = get_sha256(uploaded_file)

        self.assertEqual(
            digest,
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
        )
        self.assertEqual(uploaded_file.tell(), 3)

    def test_upload_form_sets_sample_metadata(self):
        uploaded_file = SimpleUploadedFile(
            "sample.eml",
            b"From: sender@example.com\r\n\r\nBody",
            content_type="message/rfc822",
        )
        form = UploadFileForm(files={"file": uploaded_file})

        self.assertTrue(form.is_valid(), form.errors)
        sample = form.save()

        self.assertEqual(sample.original_name, "sample.eml")
        self.assertEqual(sample.status, "queued")
        self.assertEqual(len(sample.sha256), 64)


class AuthenticationStatusTests(TestCase):
    def test_extracts_spf_dkim_and_dmarc_results(self):
        statuses = extract_authentication_statuses(
            "mx.test; spf=pass smtp.mailfrom=example.com; "
            "dkim=fail header.d=example.com; dmarc=pass header.from=example.com"
        )

        self.assertEqual(statuses["spf"]["result"], "pass")
        self.assertTrue(statuses["spf"]["passed"])
        self.assertEqual(statuses["dkim"]["result"], "fail")
        self.assertFalse(statuses["dkim"]["passed"])
        self.assertEqual(statuses["dmarc"]["result"], "pass")

    def test_uses_received_spf_as_fallback(self):
        statuses = extract_authentication_statuses("", "softfail (sender not permitted)")

        self.assertEqual(statuses["spf"]["result"], "softfail")
        self.assertEqual(statuses["dkim"]["result"], "unknown")
        self.assertEqual(statuses["dmarc"]["result"], "unknown")


class IndependentAuthenticationTests(TestCase):
    @patch("core.email_authentication._fetch_dmarc_record", return_value="v=DMARC1; p=reject")
    @patch("core.email_authentication.dkim.verify", return_value=True)
    @patch("core.email_authentication.spf.check2", return_value=("pass", "sender SPF authorized"))
    def test_verifies_spf_dkim_and_dmarc_alignment(self, _spf, _dkim, _dmarc):
        raw_email = (
            b"Return-Path: <sender@example.com>\r\n"
            b"Received: from mail.example.com (mail.example.com [203.0.113.25])\r\n"
            b"    by mx.test with ESMTPS id 123\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; bh=x; b=y\r\n"
            b"From: Sender <sender@example.com>\r\n"
            b"To: Receiver <receiver@example.net>\r\n"
            b"Subject: Auth Test\r\n"
            b"\r\n"
            b"Body"
        )
        headers = {
            "return-path": ["<sender@example.com>"],
            "received": [
                "from mail.example.com (mail.example.com [203.0.113.25]) by mx.test"
            ],
            "dkim-signature": ["v=1; a=rsa-sha256; d=example.com; s=mail; bh=x; b=y"],
            "from": ["Sender <sender@example.com>"],
        }

        result = verify_email_authentication(raw_email, headers)

        self.assertEqual(result["spf"]["result"], "pass")
        self.assertEqual(result["dkim"]["result"], "pass")
        self.assertEqual(result["dmarc"]["result"], "pass")
        self.assertTrue(result["dmarc"]["metadata"]["spf_aligned"])

    @patch("core.email_authentication._fetch_dmarc_record", return_value="")
    def test_spf_unknown_without_sender_ip(self, _dmarc):
        result = verify_email_authentication(
            b"From: Sender <sender@example.com>\r\n\r\nBody",
            {"from": ["Sender <sender@example.com>"]},
        )

        self.assertEqual(result["spf"]["result"], "unknown")
        self.assertEqual(result["spf"]["source"], "Independent SPF")

    @patch("core.email_authentication._fetch_dmarc_record", return_value="v=DMARC1; p=reject")
    @patch("core.email_authentication.dkim.verify", return_value=False)
    @patch("core.email_authentication.spf.check2", return_value=("fail", "sender SPF unauthorized"))
    def test_prefers_receiver_reported_authentication_results(self, _spf, _dkim, _dmarc):
        raw_email = (
            b"Return-Path: <sender@example.com>\r\n"
            b"Received: from mail.example.com (mail.example.com [203.0.113.25]) by mx.test\r\n"
            b"Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com; "
            b"dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; bh=x; b=y\r\n"
            b"From: Sender <sender@example.com>\r\n"
            b"\r\n"
            b"Body"
        )
        headers = {
            "return-path": ["<sender@example.com>"],
            "received": ["from mail.example.com (mail.example.com [203.0.113.25]) by mx.test"],
            "authentication-results": [
                "mx.test; spf=pass smtp.mailfrom=example.com; "
                "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
            ],
            "dkim-signature": ["v=1; a=rsa-sha256; d=example.com; s=mail; bh=x; b=y"],
            "from": ["Sender <sender@example.com>"],
        }

        result = verify_email_authentication(raw_email, headers)

        self.assertEqual(result["spf"]["result"], "pass")
        self.assertEqual(result["dkim"]["result"], "pass")
        self.assertEqual(result["dmarc"]["result"], "pass")
        self.assertEqual(result["spf"]["source"], "Authentication-Results")
        self.assertEqual(result["spf"]["metadata"]["independent"]["result"], "fail")

    @patch("core.email_authentication._fetch_dmarc_record", return_value="v=DMARC1; p=reject")
    def test_dmarc_unknown_when_local_authentication_is_inconclusive(self, _dmarc):
        result = verify_email_authentication(
            b"From: Sender <sender@example.com>\r\n\r\nBody",
            {"from": ["Sender <sender@example.com>"]},
        )

        self.assertEqual(result["spf"]["result"], "unknown")
        self.assertEqual(result["dkim"]["result"], "unknown")
        self.assertEqual(result["dmarc"]["result"], "unknown")


class LookupTests(TestCase):
    @patch("core.lookup._fetch_virustotal", return_value={"available": False})
    @patch("core.lookup._fetch_rdap", return_value={})
    @patch("core.lookup._resolve_domain", return_value=["93.184.216.34"])
    def test_normalizes_email_lookup_to_domain(self, _resolve_domain, _fetch_rdap, _fetch_virustotal):
        result = lookup_indicator("Sender Example <sender@example.com>")

        self.assertEqual(result["type"], "email")
        self.assertEqual(result["normalized"], "sender@example.com")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["ip_addresses"], ["93.184.216.34"])
        _fetch_virustotal.assert_called_once_with("email", "sender@example.com", "example.com", "")

    @patch("core.lookup._fetch_virustotal", return_value={"available": True, "malicious": 2})
    @patch("core.lookup._fetch_rdap", return_value={})
    @patch("core.lookup._resolve_domain", return_value=["93.184.216.34"])
    def test_normalizes_url_lookup_for_virustotal(self, _resolve_domain, _fetch_rdap, _fetch_virustotal):
        result = lookup_indicator("https://example.com/login")

        self.assertEqual(result["type"], "url")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["virustotal"]["malicious"], 2)
        _fetch_virustotal.assert_called_once_with("url", "https://example.com/login", "example.com", "")

    def test_virustotal_url_identifier_is_unpadded_urlsafe_base64(self):
        self.assertEqual(_virustotal_url_id("https://example.com/"), "aHR0cHM6Ly9leGFtcGxlLmNvbS8")

    @patch(
        "core.lookup.urlopen",
        return_value=type(
            "Response",
            (),
            {
                "__enter__": lambda self: self,
                "__exit__": lambda self, *args: None,
                "read": lambda self: json.dumps(
                    {
                        "handle": "NET-203-0-113-0-1",
                        "entities": [
                            {
                                "roles": ["technical"],
                                "vcardArray": [
                                    "vcard",
                                    [["fn", {}, "text", "Network Operations"]],
                                ],
                                "entities": [
                                    {
                                        "roles": ["registrant"],
                                        "vcardArray": [
                                            "vcard",
                                            [["org", {}, "text", "Example Network Owner"]],
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ).encode("utf-8"),
            },
        )(),
    )
    def test_rdap_owner_uses_nested_registrant_entity(self, _urlopen):
        result = _fetch_rdap("ip", "203.0.113.1")

        self.assertEqual(result["owner"], "Example Network Owner")
        self.assertEqual(result["name"], "")
        self.assertIn(
            {"roles": ["registrant"], "name": "Example Network Owner"},
            result["entities"],
        )

    def test_load_env_file_sets_missing_values_without_overriding_existing_environment(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as env_file:
            env_file.write("VT_KEY=from-file\nEXISTING_KEY=from-file\n")
            env_file.flush()

            with patch.dict(os.environ, {"EXISTING_KEY": "from-env"}, clear=False):
                os.environ.pop("VT_KEY", None)
                load_env_file(Path(env_file.name))

                self.assertEqual(os.environ["VT_KEY"], "from-file")
                self.assertEqual(os.environ["EXISTING_KEY"], "from-env")


class UrlAnalysisTests(TestCase):
    @patch("core.url_analysis._expand_redirects", return_value=("http://bit.ly/a", ["http://bit.ly/a"], ""))
    @patch("core.url_analysis._resolve_domain", return_value=["93.184.216.34"])
    def test_flags_shortener_and_non_https_url(self, _resolve_domain, _expand_redirects):
        result = analyze_urls(["http://bit.ly/a"])[0]

        self.assertEqual(result["domain"], "bit.ly")
        self.assertEqual(result["risk"], "suspicious")
        self.assertIn("url_shortener", result["flags"])
        self.assertIn("non_https", result["flags"])

    @patch("core.url_analysis._expand_redirects", return_value=("https://example.com/path", ["https://example.com/path"], ""))
    @patch("core.url_analysis._resolve_domain", return_value=["93.184.216.34"])
    def test_clean_https_url_with_dns_resolution(self, _resolve_domain, _expand_redirects):
        result = analyze_urls(["https://example.com/path"])[0]

        self.assertEqual(result["risk"], "clean")
        self.assertEqual(result["flags"], [])


class RiskScoringTests(TestCase):
    def test_scores_failed_authentication_risky_attachment_and_suspicious_url(self):
        result = score_risk(
            authentication={
                "spf": {"result": "fail", "source": "Independent SPF", "details": "SPF failed"},
                "dkim": {"result": "pass", "source": "Independent DKIM", "details": ""},
                "dmarc": {"result": "fail", "source": "Independent DMARC", "details": "DMARC failed"},
            },
            attachments=[
                {
                    "filename": "invoice.exe",
                    "risky": True,
                    "risk": "risky_extension",
                }
            ],
            urls=[
                {
                    "url": "http://bit.ly/a",
                    "domain": "bit.ly",
                    "risk": "suspicious",
                    "flags": ["non_https", "url_shortener"],
                }
            ],
            sender="Sender <sender@example.com>",
            return_path="<bounce@mailer.test>",
            received_path=["hop"] * 6,
        )

        finding_ids = {finding["id"] for finding in result["findings"]}

        self.assertEqual(result["score"], 100)
        self.assertEqual(result["severity"], "critical")
        self.assertIn("auth.dmarc.fail", finding_ids)
        self.assertIn("attachments.risky_extension", finding_ids)
        self.assertIn("urls.suspicious", finding_ids)
        self.assertIn("sender.return_path_mismatch", finding_ids)
        self.assertIn("routing.long_received_path", finding_ids)

    def test_clean_message_scores_low_without_findings(self):
        result = score_risk(
            authentication={
                "spf": {"result": "pass"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "pass"},
            },
            attachments=[],
            urls=[],
            sender="Sender <sender@example.com>",
            return_path="<bounce@example.com>",
            received_path=["hop"] * 2,
        )

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["severity"], "low")
        self.assertEqual(result["findings"], [])
