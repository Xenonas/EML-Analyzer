from celery import shared_task
from django.http import JsonResponse
from django.utils import timezone

from django.shortcuts import get_object_or_404

from analysis.get_headers import get_email_headers

from .models import AnalysisResult, UploadedSample


def sample_status(request, sample_id: int):
    sample = get_object_or_404(UploadedSample, id=sample_id)

    data = {
        "id": sample.id,
        "original_name": sample.original_name,
        "sha256": sample.sha256,
        "status": sample.status,
        "created_at": sample.created_at.isoformat(),
    }

    if hasattr(sample, "analysisresult"):
        result = sample.analysisresult
        data["analysis"] = {
            "subject": result.header_subject,
            "from": result.header_from,
            "to": result.header_to,
            "date": result.header_date,
            "message_id": result.header_message_id,
            "summary": result.summary,
            "verdict": result.verdict,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }
    else:
        data["analysis"] = None

    return JsonResponse(data)

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

        summary = (
            f"Parsed email successfully. "
            f"From: {sender or 'N/A'} | "
            f"To: {recipient or 'N/A'} | "
            f"Subject: {subject or 'N/A'}"
        )

        verdict = "parsed"

        AnalysisResult.objects.update_or_create(
            sample=sample,
            defaults={
                "header_subject": subject,
                "header_from": sender,
                "header_to": recipient,
                "header_date": headers.get("Date", ""),
                "header_message_id": headers.get("Message-ID", ""),
                "summary": summary,
                "verdict": verdict,
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