import json
import re
import jwt
import bcrypt

from django.http      import JsonResponse
from django.views     import View
from django.db.models import Q
from django.db        import IntegrityError

from .models          import User
from my_settings      import SECRET_KEY, ALGORITHM, validate_email, validate_nickname, PASSWORD_LENGTH
from spaces.views     import SpaceCardView
from decorators.utils import login_required, check_blank


class SignUpView(View):
    def post(self, request):
        try:
            data             = json.loads(request.body)
            password         = data["password"]
            encrypt_pw       = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")

            if not validate_nickname.match(data["nickname"]):
                return JsonResponse({"message" : "INVALID_NICKNAME"}, status = 400)
            if not validate_email.match(data["email"]):
                return JsonResponse({"message" : "INVALID_EMAIL"}, status = 400)
            if len(password) < PASSWORD_LENGTH:
                return JsonResponse({"message" : "INVALID_PASSWORD"}, status = 400)
            if User.objects.filter(Q(email = data["email"]) | Q(nickname = data["nickname"])).exists():
                return JsonResponse({"message" : "USER_ALREADY_EXISTS"}, status = 400)
            User(
                email    = data["email"],
                password = encrypt_pw,
                nickname = data["nickname"]).save()
            return JsonResponse({"message" : "SIGNUP_SUCCES"}, status = 201)
        except KeyError:
            return JsonResponse({"message" : "KEY_ERROR"}, status = 400)


class SignInView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)

            if User.objects.filter(email = data["email"]).exists():
                user = User.objects.get(email = data["email"])
                if bcrypt.checkpw(data["password"].encode(), user.password.encode()):
                    token = jwt.encode({"id" : user.id}, SECRET_KEY, ALGORITHM)
                    return JsonResponse({"TOKEN" : token}, status = 200)
                return JsonResponse({"message" : "INVALID_PASSWORD"}, status =401)
            return JsonResponse({"message" : "INVALID_USER"}, status = 401)
        except KeyError:
            return JsonResponse({"message" : "KEY_ERROR"}, status = 401)
        except ValueError:
            return JsonResponse({"message" : "VALUE_ERROR"}, status = 401)
   

class UserProfileView(View):
    @login_required
    def get(self, request):
        user        = request.user
        user_data   = {
            "nickname":user.nickname,
            "avatar_url":user.avatar_image,
            "email":user.email,
            "phone_numger":user.phone_number,
        }
        return JsonResponse({"user_date":user_data}, status = 200)

    @login_required
    def patch(self, request):
        try:
            data             = json.loads(request.body)
            user             = request.user
            hash_password    = lambda x : bcrypt.hashpw(x.encode("utf-8"), bcrypt.gensalt()).decode()
            user.email       = data["email"] if "email" in data.__iter__()  else user.email
            user.password    = hash_password(data["password"]) if "password" in data.__iter__() else user.password
            user.nickname    = data["nickname"] if "nickname" in data.__iter__() else user.nickname
            user.save()
            return JsonResponse({"message":"SUCCESS"}, status = 200)
        except IntegrityError:
            return JsonResponse({"message":"ALREADY_EXIST"}, status = 200)
    
    @login_required
    def delete(self, request):
        user = request.user
        user.delete()
        return JsonResponse({"message":"SUCCESS"}, status = 200)


class UserLikeView(SpaceCardView):
    @login_required
    def get(self, request):
        super().get(request)
        user            = request.user
        like_card_id    = [like.space.id for like in user.like_set.all()]
        like_space_card = []

        for card in self.space_card:
            space_id = card.get("id")
            if space_id in like_card_id:
                like_space_card.append(card)
        return JsonResponse({"like_card":like_space_card}, status = 200)