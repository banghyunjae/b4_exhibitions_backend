from django.db import models
from users.models import User


class Exhibition(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    info_name = models.CharField("전시회 이름", max_length=255)
    content = models.TextField("전시회 내용", blank=True, null=True)
    location = models.CharField("전시회 장소", blank=True, null=True, max_length=255)
    image = models.ImageField(
        "이미지", blank=True, null=True, upload_to="exhibitions/%Y/%m/"
    )
    created_at = models.DateTimeField("생성시간", auto_now_add=True)
    updated_at = models.DateTimeField("수정시간", auto_now=True)
    likes = models.ManyToManyField(User, related_name="exhibition_likes", blank=True)
    category = models.CharField("카테고리", max_length=255, blank=True, null=True)
    direct_url = models.URLField("바로가기url", max_length=255, blank=True, null=True)
    start_date = models.DateField("시작일", blank=True, null=True)
    end_date = models.DateField("종료일", blank=True, null=True)
    svstatus = models.CharField("서비스상태", max_length=255)
    longitude = models.FloatField("경도", blank=True, null=True)
    latitude = models.FloatField("위도", blank=True, null=True)

    def __str__(self):
        return str(self.info_name)

    def total_likes(self):
        return self.likes.count()
