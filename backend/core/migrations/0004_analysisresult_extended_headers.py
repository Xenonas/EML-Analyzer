from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_replace_raw_headers_with_structured_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="analysisresult",
            name="header_authentication_results",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_dkim_signature",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_reply_to",
            field=models.CharField(blank=True, max_length=998),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_return_path",
            field=models.CharField(blank=True, max_length=998),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_spf",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="header_user_agent",
            field=models.CharField(blank=True, max_length=998),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="received_hops",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="analysisresult",
            name="received_path",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
