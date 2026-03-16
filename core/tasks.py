from celery import shared_task
from django.utils import timezone

from analysis.get_headers import get_email_headers

from .models import AnalysisResult, UploadedSample


@shared_task
def analyze_uploaded_sample(sample_id: int) -> None:
    sample = UploadedSample.objects.get(id=sample_id)
    sample.status = "processing"
    sample.save(update_fields=["status"])

    try:
        with sample.file.open("rb") as f:
            headers = get_email_headers(f)

        subject = headers.get("Subject", "")
        sender = headers.get("From", "")
        recipient = headers.get("To", "")
        received_path = headers.get("Received", [])

        summary = (
            "Parsed email successfully. "
            f"From: {sender or 'N/A'} | "
            f"To: {recipient or 'N/A'} | "
            f"Subject: {subject or 'N/A'} | "
            f"Hops: {len(received_path)}"
        )

        AnalysisResult.objects.update_or_create(
            sample=sample,
            defaults={
                "header_subject": subject,
                "header_from": sender,
                "header_to": recipient,
                "header_date": headers.get("Date", ""),
                "header_message_id": headers.get("Message-ID", ""),
                "header_reply_to": headers.get("Reply-To", ""),
                "header_return_path": headers.get("Return-Path", ""),
                "header_user_agent": headers.get("User-Agent", "") or headers.get("X-Mailer", ""),
                "header_authentication_results": headers.get("Authentication-Results", ""),
                "header_spf": headers.get("Received-SPF", "") or headers.get("X-SPF", ""),
                "header_dkim_signature": headers.get("DKIM-Signature", ""),
                "received_hops": len(received_path),
                "received_path": received_path,
                "summary": summary,
                "verdict": "parsed",
                "completed_at": timezone.now(),
            },
        )

        sample.status = "done"
        sample.save(update_fields=["status"])

    except Exception as e:
        sample.status = "failed"
        sample.save(update_fields=["status"])

        AnalysisResult.objects.update_or_create(
            sample=sample,
            defaults={
                "summary": f"Analysis failed: {str(e)}",
                "verdict": "error",
                "completed_at": timezone.now(),
            },
        )

        raise
