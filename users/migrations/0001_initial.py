# Generated by Django 4.2.2 on 2023-06-07 21:39

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        max_length=255, unique=True, verbose_name="사용자 이메일"
                    ),
                ),
                (
                    "nickname",
                    models.CharField(
                        max_length=100, unique=True, verbose_name="사용자 닉네임"
                    ),
                ),
                ("password", models.CharField(max_length=255, verbose_name="비밀번호")),
                (
                    "gender",
                    models.CharField(
                        choices=[
                            ("남성", "남성"),
                            ("여성", "여성"),
                            ("밝히고 싶지 않음", "밝히고 싶지 않음"),
                        ],
                        error_messages="필수 입력 값입니다.",
                        max_length=10,
                        verbose_name="성별",
                    ),
                ),
                (
                    "age",
                    models.PositiveIntegerField(max_length=3, verbose_name="사용자 나이"),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="아이디 생성일"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="마지막 회원정보 수정일"),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("is_admin", models.BooleanField(default=False)),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
