from django.urls import path
from . import views

urlpatterns = [
    path('register/',views.RegisterView.as_view(), name='register'),
    path('login/',views.UserLogin.as_view(), name='login'),
    path('logout/', views.LogoutAPI.as_view(), name='logout'),
    path('refresh/',views.TokenRefreshView.as_view(),name='refresh-token'),
    path('viewuser/',views.CustomUserView.as_view(),name='viewuser'),
    path('change-password/',views.ChangePasswordView.as_view(),name='change-password'),
]