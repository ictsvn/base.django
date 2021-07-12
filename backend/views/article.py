from backend.models import *
from django_filters import FilterSet, views, CharFilter


class ArticleFilter(FilterSet):
    name = CharFilter(lookup_expr='icontains')

    class Meta:
        model = Article
        fields = ['name', 'num', 'category']


class ArticleListView(views.FilterView):
    model = Article
    context_object_name = 'articles'
    template_name = 'articles.html'
    filterset_class = ArticleFilter
    paginate_by = 100
