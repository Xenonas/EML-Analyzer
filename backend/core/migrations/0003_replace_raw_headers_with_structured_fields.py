from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0002_analysisresult_uploadedsample_delete_uploadedfile_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="analysisresult",
            name="headers",
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_date",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_from",
            field=models.CharField(blank=True, max_length=998),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_message_id",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_subject",
            field=models.CharField(blank=True, max_length=998),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_to",
            field=models.TextField(blank=True),
        ),
    ]
