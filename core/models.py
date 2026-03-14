from django.db import models

class UploadedSample(models.Model):
    file = models.FileField(upload_to="uploads/")
    original_name = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=20, default="uploaded")
    created_at = models.DateTimeField(auto_now_add=True)

class AnalysisResult(models.Model):
    sample = models.OneToOneField(UploadedSample, on_delete=models.CASCADE)
    headers = models.JSONField(null=True, blank=True)
    summary = models.TextField(blank=True)
    verdict = models.CharField(max_length=50, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)