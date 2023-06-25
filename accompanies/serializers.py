from rest_framework import serializers
from accompanies.models import Accompany, Apply


class ApplySerializer(serializers.ModelSerializer):
    nickname = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()
    accompany = serializers.SerializerMethodField()

    class Meta:
        model = Apply
        fields = "__all__"

    def get_nickname(self, obj):
        return obj.user.nickname

    def get_user(self, obj):
        return obj.user.id

    def get_accompany(self, obj):
        return obj.accompany.id


class AccompanyCreateSerializer(serializers.ModelSerializer):
    nickname = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()

    class Meta:
        model = Accompany
        fields = (
            "id",
            "user",
            "nickname",
            "content",
            "personnel",
            "start_time",
            "end_time",
            "updated_at",
        )

    read_only_fields = (
        "nickname",
        "updated_at",
    )

    def get_nickname(self, obj):
        return obj.user.nickname

    def get_user(self, obj):
        return obj.user.id


class AccompanySerializer(serializers.ModelSerializer):
    applies = ApplySerializer(many=True)
    nickname = serializers.SerializerMethodField()

    class Meta:
        model = Accompany
        fields = "__all__"

    def get_nickname(self, obj):
        return obj.user.nickname
