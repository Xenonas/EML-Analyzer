from django.contrib import admin

from .models import AnalysisResult, UploadedSample


@admin.register(UploadedSample)
class UploadedSampleAdmin(admin.ModelAdmin):
    list_display = ("id", "original_name", "sha256", "status", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("original_name", "sha256")
    readonly_fields = ("created_at",)
    ordering = ("-created_at",)


@admin.register(AnalysisResult)
class AnalysisResultAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "sample",
        "header_subject",
        "header_from",
        "verdict",
        "completed_at",
    )
    list_filter = ("verdict", "completed_at")
    search_fields = (
        "sample__original_name",
        "sample__sha256",
        "header_subject",
        "header_from",
        "header_to",
        "summary",
    )
    list_display = ("id", "sample", "verdict", "completed_at")
    list_filter = ("verdict", "completed_at")
    search_fields = ("sample__original_name", "sample__sha256", "summary")
    readonly_fields = ("completed_at",)
    ordering = ("-completed_at",)
