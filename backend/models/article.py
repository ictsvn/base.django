from django.db import models


class Article(models.Model):
    class Meta:
        db_table = 'articles'
        verbose_name = 'Article'
        verbose_name_plural = 'Articles'

    name = models.CharField(max_length=255)
    num = models.IntegerField()
    category = models.ForeignKey('backend.Category', on_delete=models.SET_NULL, null=True)
