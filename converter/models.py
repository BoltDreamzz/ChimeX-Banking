# converter/models.py

from django.db import models


class Currency(models.Model):
    code = models.CharField(max_length=3, unique=True)
    rate = models.DecimalField(max_digits=10, decimal_places=6)

    def __str__(self):
        return self.code
