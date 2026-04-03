from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from .models import UploadedSample
from .tasks import analyze_uploaded_sample


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
