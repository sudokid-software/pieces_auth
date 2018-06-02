from django.conf import settings

import requests
from requests.exceptions import HTTPError

from authlib.specs.oidc import CodeIDToken
from authlib.specs.rfc7519 import JWT, errors

"""
{
    "access_token": "0123456789abcdefghijABCDEFGHIJ",
    "refresh_token": "eyJfaWQmNzMtNGCJ9%6VFV5LNrZFUj8oU231/3Aj",
    "expires_in": 3600,
    "scope": "viewing_activity_read"
}
"""


def logout(request):
    del request.session['access_token']
    del request.session['refresh_token']
    del request.session['expires_in']
    del request.session['scope']
    del request.session['preferred_username']


def login(request, response):
    request.session['access_token'] = response.get('access_token', '')
    request.session['refresh_token'] = response.get('refresh_token', '')
    request.session['scope'] = response.get('scope', '')
    request.session.modified = True
    request.session.save()


def validate_token(response):
    id_token = response.get('id_token', None)
    keys = requests.get('https://id.twitch.tv/oauth2/keys').json()
    jwt = JWT()
    claims = jwt.decode(id_token, keys, claims_cls=CodeIDToken)

    try:
        claims.validate()
    except errors.InvalidClaimError:
        pass
    except errors.InvalidTokenError:
        pass


def refresh(request):
    """
    curl -X POST https://id.twitch.tv/oauth2/token
        --data-urlencode
        ?grant_type=refresh_token
        &refresh_token=<your refresh token>
        &client_id=<your client ID>
        &client_secret=<your client secret>
    :return:
    """
    refresh_token = request.session.get('refresh_token', '')
    response = requests.post((
        f'{settings.TWITCH_AUTH_URL}/oauth2/token?'
        f'grant_type=refresh_token&'
        f'refresh_token={refresh_token}&'
        f'client_id={settings.TWITCH_CLIENT_ID}&'
        f'client_secret={settings.TWITCH_CLIENT_SECRET}'
    ))

    response.raise_for_status()

    return login(request, response.json())


def post(request, url, data):
    response = requests.post(url, data=data)

    try:
        response.raise_for_status()
    except HTTPError:
        refresh(request)
        post(request, url, data)


def get(request, url, params):
    response = requests.get(url, params=params)

    try:
        response.raise_for_status()
    except HTTPError:
        refresh(request)
        get(request, url, params)
