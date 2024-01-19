from django.urls import path
from . import views

urlpatterns = [
    path('<int:product_id>/',views.ViewProduct.as_view(), name='product-post'),
    path('',views.ViewProduct.as_view(), name='product'),
]