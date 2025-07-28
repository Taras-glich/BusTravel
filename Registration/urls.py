from django.urls import path
from . import views
from .views import CustomPasswordResetConfirmView  # Додайте цей імпорт

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register_view, name='register'),
    path('verify-email/', views.verify_email_link_view, name='verify_email_link'),
    path('login/', views.login_view, name='login'),
    path('two-factor-verify/', views.two_factor_verify_view, name='two_factor_verify'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('toggle-two-factor/', views.toggle_two_factor, name='toggle_two_factor'),
    path('change-password/', views.change_password, name='change_password'),
    path('delete-account/', views.delete_account, name='delete_account'),
    path('change-language/', views.change_language, name='change_language'),
    path('restore-account/', views.cancel_account_deletion, name='restore_account'),  # Видалено дубль

    # URL для видалення акаунту
    path('account/permanent-delete/', views.permanent_delete_account_view, name='permanent_delete_account'),
    path('account/confirm-delete/', views.confirm_permanent_delete_view, name='confirm_permanent_delete'),

    # URL для скидання пароля
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('password-reset/done/', views.password_reset_done_view, name='password_reset_done'),
    path('reset/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # Використовуємо клас
    path('reset/done/', views.password_reset_complete_view, name='password_reset_complete'),
]