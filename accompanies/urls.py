from django.urls import path
from accompanies import views

urlpatterns = [
    path("<int:exhibition_id>/", views.AccompanyView.as_view(), name="accompany_view"),
    path(
        "detail/<int:accompany_id>/",
        views.AccompanyView.as_view(),
        name="accompany_view",
    ),
]
