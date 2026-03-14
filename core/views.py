# core/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UploadedFileSerializer
from analysis.get_headers import get_email_headers
from analysis.utils import get_sha256


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