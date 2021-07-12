from graphene_django import DjangoObjectType
from backend.models import User
import graphene


class UserType(DjangoObjectType):
    class Meta:
        model = User
        fields = ('id', 'username', 'extra_field')

    extra_field = graphene.String()

    def resolve_extra_field(self, info):
        return 'hello!'


class Query(graphene.ObjectType):
    users = graphene.List(UserType)

    def resolve_users(self, info):
        return User.objects.all()


schema = graphene.Schema(query=Query)
