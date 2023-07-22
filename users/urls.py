from django.urls import path
from users import views, socials
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


app_name = "users"

urlpatterns = [
    path("signup/", views.UserView.as_view(), name="user-signup"),
    path("signin/", views.CustomTokenObtainPairView.as_view(), name="user-signin"),
    path("", views.UserDetailView.as_view(), name="user-update-and-delete"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("<int:user_id>/", views.UserMypageView.as_view(), name="user-mypage"),
    path("google/", socials.GoogleSignin.as_view(), name="google-signin"),
    path("kakao/", socials.KakaoSignin.as_view(), name="kakao-signin"),
    path("naver/", socials.NaverSignin.as_view(), name="naver-signin"),
    path("github/", socials.GithubSignin.as_view(), name="github-signin"),
]
