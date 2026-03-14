from rest_framework import serializers
from .models import UploadedSample

class UploadedFileSerializer(serializers.ModelSerializer):

    class Meta:
        model = UploadedSample
        fields = ["id", "file", "created_at", "original_name", "sha256", "status"]