from rest_framework import serializers
from .models import Exhibition
from reviews.serializers import ReviewSerializer
from accompanies.serializers import AccompanySerializer


class ExhibitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exhibition
        fields = [
            "id",
            "user_id",
            "info_name",
            "content",
            "location",
            "image",
            "created_at",
            "updated_at",
            "category",
            "start_date",
            "end_date",
        ]

    def get_likes(self, obj):
        return obj.likes.count()

    # def get_image(self, obj):
    #     if obj.image:
    #         return obj.image.url
    #     return None


class ExhibitionReviewSerializer(serializers.ModelSerializer):
    """전시회 상세보기 리뷰"""

    reviews = ReviewSerializer(source="review_set", many=True)
    # accompanies = AccompanySerializer(many=True)

    class Meta:
        model = Exhibition
        fields = [
            "id",
            "user_id",
            "info_name",
            "content",
            "location",
            "image",
            "created_at",
            "updated_at",
            "category",
            "start_date",
            "end_date",
            "reviews",
            # "accompanies",
        ]


class ExhibitionAccompanySerializer(serializers.ModelSerializer):
    """전시회 상세보기 동행구하기"""

    # reviews = ReviewSerializer(source="review_set", many=True)
    accompanies = AccompanySerializer(many=True)

    class Meta:
        model = Exhibition
        fields = [
            "id",
            "user_id",
            "info_name",
            "content",
            "location",
            "image",
            "created_at",
            "updated_at",
            "category",
            "start_date",
            "end_date",
            # "reviews",
            "accompanies",
        ]
