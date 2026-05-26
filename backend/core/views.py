import hashlib

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from .authentication import extract_authentication_statuses
from .lookup import lookup_indicator
from .models import UploadedSample
from .tasks import analyze_uploaded_sample


def indicator_lookup(request):
    if request.method != "GET":
        return JsonResponse({"error": "Only GET allowed"}, status=405)

    query = request.GET.get("q", "")
    if len(query) > 512:
        return JsonResponse({"error": "Lookup value is too long."}, status=400)

    result = lookup_indicator(query)
    status = 400 if result.get("error") else 200
    return JsonResponse(result, status=status)


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
            "reply_to": result.header_reply_to,
            "return_path": result.header_return_path,
            "user_agent": result.header_user_agent,
            "body": result.body_text,
            "attachments": result.attachments,
            "urls": result.urls,
            "risk": result.risk_assessment,
            "authentication_results": result.header_authentication_results,
            "spf": result.header_spf,
            "dkim_signature": result.header_dkim_signature,
            "authentication": result.authentication_verification
            or extract_authentication_statuses(
                result.header_authentication_results,
                result.header_spf,
            ),
            "reported_authentication": extract_authentication_statuses(
                result.header_authentication_results,
                result.header_spf,
            ),
            "hops": result.received_hops,
            "received_path": result.received_path,
            "summary": result.summary,
            "verdict": result.verdict,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }
    else:
        data["analysis"] = None

    return JsonResponse(data)

@csrf_exempt
def upload_sample(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse({"error": "No file uploaded"}, status=400)

    sha256 = hashlib.sha256()
    for chunk in uploaded_file.chunks():
        sha256.update(chunk)
    file_hash = sha256.hexdigest()

    uploaded_file.seek(0)

    sample = UploadedSample.objects.create(
        file=uploaded_file,
        original_name=uploaded_file.name,
        sha256=file_hash,
        status="queued",
    )

    analyze_uploaded_sample.delay(sample.id)

    return JsonResponse(
        {
            "id": sample.id,
            "original_name": sample.original_name,
            "sha256": sample.sha256,
            "status": sample.status,
        },
        status=201,
    )
