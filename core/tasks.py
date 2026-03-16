from celery import shared_task
from django.utils import timezone

from analysis.get_headers import get_email_headers

from .models import AnalysisResult, UploadedSample


def _get_first(headers: dict, *names: str) -> str:
    for name in names:
        values = headers.get(name.lower(), [])
        if values:
            return values[0]
    return ""


def _get_joined(headers: dict, *names: str) -> str:
    parts = []
    for name in names:
        parts.extend(headers.get(name.lower(), []))
    return "\n".join(part for part in parts if part)


@shared_task
def analyze_uploaded_sample(sample_id: int) -> None:
    sample = UploadedSample.objects.get(id=sample_id)
    sample.status = "processing"
    sample.save(update_fields=["status"])

    try:
        with sample.file.open("rb") as f:
            headers = get_email_headers(f)

        subject = _get_first(headers, "subject")
        sender = _get_first(headers, "from")
        recipient = _get_first(headers, "to")
        received_path = headers.get("received", [])

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
                "header_date": _get_first(headers, "date"),
                "header_message_id": _get_first(headers, "message-id"),
                "header_reply_to": _get_first(headers, "reply-to"),
                "header_return_path": _get_first(headers, "return-path"),
                "header_user_agent": _get_first(headers, "user-agent", "x-mailer"),
                "header_authentication_results": _get_joined(headers, "authentication-results"),
                "header_spf": _get_joined(headers, "received-spf", "x-spf"),
                "header_dkim_signature": _get_joined(headers, "dkim-signature"),
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
