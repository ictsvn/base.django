from backend.models import User

import json

from graphene_django.utils.testing import GraphQLTestCase
from base.schema import schema

# Create your tests here.


class GrapheneTest(GraphQLTestCase):
    GRAPHQL_SCHEMA = schema
    GRAPHQL_URL = "/graphql"

    def setUp(self):
        user = User.objects.create(
            username="admin", email="admin@icts.vn", is_staff=True, is_superuser=True)
        return None

    # def test_Graphene(self):
    #     ma = LogEntryAdmin(LogEntry, self.log_entry)
    #     self.assertEqual(str(ma), 'admin.LogEntryAdmin')

    def test_some_query(self):
        response = self.query(
            '''
            query {
                users {
                    id,
                    username,
                    extraField
                }
            }
            '''
        )

        content = json.loads(response.content)
        self.assertEqual(content['data']['users'][0]['username'], "admin")
        self.assertEqual(content['data']['users'][0]['extraField'], "hello!")
        self.assertEqual(len(content['data']['users']), 1)

        # This validates the status code and if you get errors
        self.assertResponseNoErrors(response)
