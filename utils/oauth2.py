import requests


def get_google_user_info(access_token):
    request = requests.get('https://www.googleapis.com/oauth2/v2/userinfo',
                           headers={'Authorization': f'Bearer {access_token}'})
    if request.status_code == 200:
        user_infos = request.json()
        return {
            'username': user_infos.get('id'),
            'email': user_infos.get('email'),
            # 'profile_pic': user_infos["picture"],
            'first_name': user_infos.get('first_name', ''),
            'last_name': user_infos.get('last_name', '')
        }
    raise ValueError(request.text)


def get_facebook_user_info(access_token):
    request = requests.get(
        f'https://graph.facebook.com/v14.0/me?fields=id%2Cname%2Cfirst_name%2Clast_name&access_token={access_token}')
    if request.status_code == 200:
        user_infos = request.json()
        return {
            'username': user_infos.get('id'),
            'email': user_infos.get('email', ''),
            # 'profile_pic': user_infos["picture"],
            'first_name': user_infos.get('first_name', ''),
            'last_name': user_infos.get('last_name', '')
        }
    raise ValueError(request.text)
