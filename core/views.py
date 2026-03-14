# core/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UploadedFileSerializer
from analysis.get_headers import get_email_headers
from analysis.utils import get_sha256

import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UploadedSample
from .tasks import analyze_uploaded_sample

from django.shortcuts import get_object_or_404

from .models import UploadedSample


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
            "headers": result.headers,
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


class FileUploadAPI(APIView):

    def post(self, request):

        data = request.data.copy()
        data["original_name"] = request.FILES["file"].name
        data["status"] = "pending"
        data["sha256"] = get_sha256(request.FILES["file"])
        serializer = UploadedFileSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)