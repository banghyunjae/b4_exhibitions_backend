from rest_framework.generics import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Exhibition
from .serializers import ExhibitionSerializer


class ExhibitionView(APIView):
    def get(self, request):  # 전시회 목록 불러오기
        exhibitions = Exhibition.objects.all()
        serializer = ExhibitionSerializer(exhibitions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):  # 전시회 작성
        serializer = ExhibitionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "게시글이 등록되었습니다."}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": "요청이 올바르지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
