from rest_framework.views import APIView
from rest_framework import status
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import get_object_or_404

from users.models import User
from users.serializers import (
    CustomTokenObtainPairSerializer,
    UserSerializer,
    UserMypageSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken


class UserView(APIView):
    def post(self, request):
        password = request.data["password"]
        password_check = request.data["password_check"]
        email = request.data["email"]
        if User.objects.filter(email=email).exists():
            return Response(
                {"message": "이미 사용 중인 이메일입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        elif password != password_check:
            return Response(
                {"message": "재확인 비밀번호가 일치하지 않습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "회원가입이 완료되었습니다."}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):  # 토큰 부여하는 코드 = 로그인
    serializer_class = CustomTokenObtainPairSerializer


class UserDetailView(APIView):
    def patch(self, request):
        """회원 정보를 수정합니다."""
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "회원 정보가 수정되었습니다."}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"message": f"${serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST
            )

    def delete(self, request):
        """회원 계정을 비활성화합니다."""
        user = request.user
        user.is_active = False
        user.save()
        return Response({"message": "탈퇴되었습니다."})


# 마이페이지
class UserMypageView(APIView):
    def get(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        serializer = UserMypageSerializer(user)

        return Response(serializer.data)
