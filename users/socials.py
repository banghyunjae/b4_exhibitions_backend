from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import User
from users.serializers import CustomTokenObtainPairSerializer
import os
import requests
from django.db import IntegrityError


KAKAO_API_KEY = os.environ.get("KAKAO_API_KEY")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
NAVER_API_KEY = os.environ.get("NAVER_API_KEY")
NAVER_API_SECRET = os.environ.get("NAVER_API_SECRET")
GITHUB_API_KEY = os.environ.get("GITHUB_API_KEY")
GITHUB_API_SECRET = os.environ.get("GITHUB_API_SECRET")


class KakaoSignin(APIView):
    """카카오 소셜 로그인"""

    def get(self, request):
        return Response(KAKAO_API_KEY, status=status.HTTP_200_OK)

    def post(self, request):
        user_data = get_social_user_data(request.data.get("code"), "kakao")
        if user_data is None:
            return Response({"error": "카카오 인증에 실패했습니다."}, status=status.HTTP_400_BAD_REQUEST)
        user, token = social_signin(user_data)
        if user:
            return Response(token, status=status.HTTP_200_OK)
        else:
            return Response(token, status=status.HTTP_400_BAD_REQUEST)


class GoogleSignin(APIView):
    """구글 소셜 로그인"""

    def get(self, request):
        return Response(GOOGLE_API_KEY, status=status.HTTP_200_OK)

    def post(self, request):
        user_data = get_social_user_data(request.data.get("access_token"), "google")
        if user_data is None:
            return Response({"error": "구글 인증에 실패했습니다."}, status=status.HTTP_400_BAD_REQUEST)
        user, token = social_signin(user_data)
        if user:
            return Response(token, status=status.HTTP_200_OK)
        else:
            return Response(token, status=status.HTTP_400_BAD_REQUEST)


class NaverSignin(APIView):
    """네이버 소셜 로그인"""

    def get(self, request):
        return Response(NAVER_API_KEY, status=status.HTTP_200_OK)

    def post(self, request):
        user_data = get_social_user_data(request.data.get("access_token"), "naver")
        if user_data is None:
            return Response({"error": "네이버 인증에 실패했습니다."}, status=status.HTTP_400_BAD_REQUEST)
        user, token = social_signin(user_data)
        if user:
            return Response(token, status=status.HTTP_200_OK)
        else:
            return Response(token, status=status.HTTP_400_BAD_REQUEST)


class GithubSignin(APIView):
    """깃헙 소셜 로그인"""

    def get(self, request):
        return Response(GITHUB_API_KEY, status=status.HTTP_200_OK)

    def post(self, request):
        user_data = get_social_user_data(request.data.get("access_token"), "github")
        if user_data is None:
            return Response({"error": "깃헙 인증에 실패했습니다."}, status=status.HTTP_400_BAD_REQUEST)
        user, token = social_signin(user_data)
        if user:
            return Response(token, status=status.HTTP_200_OK)
        else:
            return Response(token, status=status.HTTP_400_BAD_REQUEST)


def get_social_user_data(auth_code, signin_type):
    auth_code = auth_code
    if signin_type == "kakao":
        url = "https://kauth.kakao.com/oauth/token"
        headers = {"Content-type": "application/x-www-form-urlencoded;charset=utf-8"}
        data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_API_KEY,
            "redirect_uri": "http://localhost:8000/users/kakao/",
            "code": auth_code,
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            return None
        access_token = response.json().get("access_token")
        url = "https://kapi.kakao.com/v2/user/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        user_data = response.json()
        user_data["signin_type"] = signin_type
        return user_data
    elif signin_type == "google":
        url = "https://oauth2.googleapis.com/token"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "code": auth_code,
            "client_id": GOOGLE_API_KEY,
            "client_secret": GOOGLE_API_KEY,
            "redirect_uri": "http://localhost:8000/users/google/",
            "grant_type": "authorization_code",
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            return None
        access_token = response.json().get("access_token")
        url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        user_data = response.json()
        user_data["signin_type"] = signin_type
        return user_data
    elif signin_type == "naver":
        url = "https://nid.naver.com/oauth2.0/token"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "authorization_code",
            "client_id": NAVER_API_KEY,
            "client_secret": NAVER_API_SECRET,
            "redirect_uri": "http://localhost:8000/users/naver/",
            "code": auth_code,
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            return None
        access_token = response.json().get("access_token")
        url = "https://openapi.naver.com/v1/nid/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        user_data = response.json().get(
            "response"
        )  # Naver's user data is wrapped in a 'response' field
        user_data["signin_type"] = signin_type
        return user_data
    elif signin_type == "github":
        url = "https://github.com/login/oauth/access_token"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": GITHUB_API_KEY,
            "client_secret": GITHUB_API_SECRET,
            "code": auth_code,
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code != 200:
            return None
        access_token = response.text.split("&")[0].split("=")[
            1
        ]  # Github returns 'access_token' in text format
        url = "https://api.github.com/user"
        headers = {"Authorization": f"token {access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        user_data = response.json()
        user_data["signin_type"] = signin_type
        return user_data
    else:
        return None


def social_signin(user_data):
    if user_data is None:
        return None, {"error": "잘못된 접근입니다"}

    user = User.objects.filter(email=user_data["email"]).first()
    if user:
        if user.signin_type != user_data["signin_type"]:
            return None, {"error": "이미 가입된 계정이 있습니다!"}
        else:
            token = RefreshToken.for_user(user)
            token["email"] = user.email
            token["is_admin"] = user.is_admin
            token["nickname"] = user.nickname
            token["signin_type"] = user.signin_type
            return user, {"token": str(token)}
    else:
        try:
            user = User.objects.create(
                email=user_data["email"],
                nickname=user_data["nickname"],
                signin_type=user_data["signin_type"],
            )
        except IntegrityError:
            return None, {"error": "이미 존재하는 이메일입니다. 다른 이메일로 시도해주세요."}
        token = RefreshToken.for_user(user)
        token["email"] = user.email
        token["is_admin"] = user.is_admin
        token["nickname"] = user.nickname
        token["signin_type"] = user.signin_type
        return user, {"token": str(token)}
