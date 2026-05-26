# core/urls.py

from django.urls import path
from .views import indicator_lookup, upload_sample, sample_status

urlpatterns = [
    path("api/lookup/", indicator_lookup, name="indicator_lookup"),
    path("api/upload/", upload_sample, name="upload_sample"),
    path("api/upload/<int:sample_id>/", sample_status, name="sample_status"),
]
