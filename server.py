"""
A highly-simplified implementation of python-social-auth
for CherryPy
"""

__requires__ = ['cherrypy', 'keyring', 'social-auth-core']

import collections
import os

import cherrypy
import keyring
import social_core.backends.facebook
import social_core.strategy
import social_core.storage
from social_core.actions import do_auth, do_complete, do_disconnect


# You need to set up an app in Facebook and configure the key and secret
# here.
# You also need to update the app according to
# https://www.nextscripts.com/instructions/facebook-social-networks-auto-poster-setup-installation/october-2017-facebook-changes/

settings = collections.defaultdict(
	SOCIAL_AUTH_FACEBOOK_KEY='152016898808901',
	SOCIAL_AUTH_FACEBOOK_SECRET=keyring.get_password(
		'Facebook', '152016898808901'),

	SOCIAL_AUTH_PIPELINE=(
		'social_core.pipeline.social_auth.social_details',
		'social_core.pipeline.social_auth.social_uid',
		'social_core.pipeline.social_auth.auth_allowed',
		'social_core.pipeline.social_auth.social_user',
		'social_core.pipeline.social_auth.associate_user',
		'social_core.pipeline.social_auth.load_extra_data',
		'social_core.pipeline.user.user_details',
	),
)


class User(social_core.storage.UserMixin):
	def get_social_auth(provider, uid):
		return

	def username_max_length():
		return

	def user_exists(username):
		return False

	def create_user():
		return None

	def user_model():
		return dict


class NullStorage(social_core.storage.BaseStorage):
	user = User


class Auth:
	@cherrypy.expose
	def index(self):
		return '<a href="login">login</a>'

	@staticmethod
	def get_backend():
		return social_core.backends.facebook.FacebookOAuth2(
			strategy=Strategy(
				storage=NullStorage(),
			),
			redirect_uri='/auth/complete/',
		)

	@cherrypy.expose
	def login(self):
		return do_auth(self.get_backend())

	@cherrypy.expose
	def complete(self, *args, **kwargs):
		backend = self.get_backend()
		user = getattr(cherrypy.request, 'user', None)
		return do_complete(backend, self.do_login, user=user, *args, **kwargs)

	def disconnect(self, backend, association_id=None):
		user = getattr(cherrypy.request, 'user', None)
		return do_disconnect(self.get_backend(), user, association_id)

	def do_login(self, backend, user, social_user):
		print("Logged in", user, social_user)


class Strategy(social_core.strategy.BaseStrategy):
	def get_setting(self, name):
		print("Attempt to get setting", name)
		return settings.get(name) or os.environ[name]

	def request_data(self, merge=True):
		return cherrypy.request.params

	def request_host(self):
		return cherrypy.request.base

	def redirect(self, url):
		raise cherrypy.HTTPRedirect(url)

	def html(self, content):
		return content

	def session_get(self, name, default=None):
		return cherrypy.session.get(name, default)

	def session_set(self, name, value):
		cherrypy.session[name] = value

	def session_pop(self, name):
		cherrypy.session.pop(name, None)

	def session_setdefault(self, name, value):
		return cherrypy.session.setdefault(name, value)

	def build_absolute_uri(self, path=None):
		return cherrypy.url(path or '')


class Server:
	auth = Auth()

	@classmethod
	def run(cls):
		config = {
			'global': {
				'server.socket_host': '::0',
			},
			'/': {
				'tools.sessions.on': True,
			},
		}
		cherrypy.quickstart(cls(), config=config)


__name__ == '__main__' and Server.run()
