import importlib
from django.contrib.auth import get_user_model
from django.conf import settings
from firebase_admin import auth
import jwt
from firebase_auth.apps import firebase_app
from firebase_auth.forms import UserRegistrationForm

User = get_user_model()


class FirebaseAuthentication:

    def _get_auth_token(self, request):
        authorization = request.META.get('HTTP_AUTHORIZATION')
        if authorization:
            encoded_token = authorization.replace('jwt ', '')
        else:
            return None
        decoded_token = None

        try:
            # TODO: don't forget to dealwith this
            # decoded_token = auth.verify_id_token(encoded_token, firebase_app, False)
            decoded_token = jwt.decode(encoded_token, verify= False)
        except ValueError:
            pass
        except auth.InvalidIdTokenError:
            pass
        except auth.ExpiredIdTokenError:
            pass
        except auth.RevokedIdTokenError:
            pass
        except jwt.exceptions.DecodeError:
            pass 
            
        return decoded_token

    def _register_unregistered_user(self, firebase_uid):
        user = None
        form = UserRegistrationForm(data={
            'firebase_uid': firebase_uid,
        })

        if form.is_valid():
            user = form.save()
        errors = form.errors
        return user

    def _get_user_from_token(self, decoded_token):
        # TODO: uid shoud be used on verify_id_token
        firebase_uid = decoded_token.get('user_id')
        user = None

        try:
            user = User.objects.get(firebase_uid=firebase_uid)
        except User.DoesNotExist:
            # user = self._register_unregistered_user(firebase_uid)
            if hasattr(settings, 'REGISTER_FIREBASE_USER'):
                module = settings.REGISTER_FIREBASE_USER.split(".")

                m = importlib.import_module(".".join(module[0: -1]))
                register_user = getattr(m, module[-1])
                user = register_user(firebase_uid, decoded_token)
            else:
                raise Exception("REGISTER_FIREBASE_USER setting is required.")
        return user

    def authenticate(self, request, **kwargs):
        user = None
        decoded_token = self._get_auth_token(request)

        if decoded_token:
            user = self._get_user_from_token(decoded_token)
        return user

    def get_user(self, user_pk):
        try:
            user = User.objects.get(pk=user_pk)
        except User.DoesNotExist:
            user = None
        return user
