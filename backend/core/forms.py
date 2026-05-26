from django import forms

from analysis.utils import get_sha256

from .models import UploadedSample


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedSample
        fields = ["file"]

    def save(self, commit=True):
        sample = super().save(commit=False)
        uploaded_file = self.cleaned_data["file"]
        sample.original_name = uploaded_file.name
        sample.sha256 = get_sha256(uploaded_file)
        sample.status = "queued"

        if commit:
            sample.save()

        return sample
