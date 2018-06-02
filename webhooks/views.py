import logging
import json

from django.conf import settings
from django.views import View
from django.shortcuts import render
from django.shortcuts import redirect

from rest_framework import viewsets

import requests
from authlib.specs.oidc import CodeIDToken
from authlib.specs.rfc7519 import JWT, errors

from .helpers import twitch_oauth


logger = logging.getLogger(__name__)


class AuthView(View):
    template_name = 'webhooks/index.html'

    @staticmethod
    def get(_request, *_args, **_kwargs):
        redirect_uri = (
            f'{settings.TWITCH_AUTH_URL}/oauth2/authorize?'
            f'response_type=code&client_id={settings.TWITCH_CLIENT_ID}&'
            f'redirect_uri={settings.TWITCH_REDIRECT_URI}&scope=viewing_activity_read+openid&'
            f'state=c3ab8aa609ea11e793ae92361f002671'
        )
        return redirect(redirect_uri)


class UserLoggedInView(View):
    template_name = 'webhooks/index.html'

    def get(self, request, *_args, **_kwargs):
        return render(request, self.template_name, {})


class BotPanelView(View):
    template_name = 'webhooks/index.html'

    @staticmethod
    def get(request, *_args, **_kwargs):
        """
        POST https://id.twitch.tv/oauth2/token
            ?client_id=uo6dggojyb8d6soh92zknwmi5ej1q2
            &client_secret=nyo51xcdrerl8z9m56w9w6wg
            &grant_type=authorization_code
            &redirect_uri=http://localhost
            &code=394a8bc98028f39660e53025de824134fb46313

            {'status': 400, 'message': 'Parameter redirect_uri does not match registered URI'}
        :param request:
        :param _args:
        :param _kwargs:
        :return:
        """
        code = request.GET.get('code', None)

        response = requests.post((
            f'{settings.TWITCH_AUTH_URL}/oauth2/token?'
            f'client_id={settings.TWITCH_CLIENT_ID}&'
            f'client_secret={settings.TWITCH_CLIENT_SECRET}&'
            f'grant_type=authorization_code&'
            f'redirect_uri={settings.TWITCH_REDIRECT_URI}&'
            f'code={code}'
        )).json()

        try:
            twitch_oauth.validate_token(response)
            twitch_oauth.login(request, response)
        except errors.InvalidClaimError:
            pass
        except errors.InvalidTokenError:
            pass

        return redirect('/bot-panel/user/')
