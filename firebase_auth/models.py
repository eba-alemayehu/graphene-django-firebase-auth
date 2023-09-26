from django.db import models


class FirebaseAuthMixin(models.Model):
    firebase_uid = models.CharField(max_length=40, null=True, blank=True)

    class Meta:
        abstract = True
