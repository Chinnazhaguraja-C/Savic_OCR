from django.urls import path
from inte.views import (
    upload_invoice, push_to_sap, login_view, reset_password_view,
    drop_menu_view, register_page_view, UserRegisterView, upload_page_view,
    home_page_view, verify_otp_view, logout_view, forgot_password_view,
    folderupload_page_view, OTPRequestView, VerifyOTPView, ForgotPasswordView,
    upload_excel, excel_upload_page_view, download_excel,search_po_or_invoice_number,
)

urlpatterns = [
    path('', home_page_view, name='home_page_view'),
    path('upload_invoice', upload_invoice, name='upload_invoice'),
    path('push-to-sap/', push_to_sap, name='push_to_sap'),
    path('login.html', login_view, name='login'),
    path('reset-password.html', reset_password_view, name='reset_password'),
    path('drop-menu.html', drop_menu_view, name='drop_menu'),
    path('register.html', register_page_view, name='register_view'),
    path('register/', UserRegisterView.as_view(), name='register'),
    path('upload.html', upload_page_view, name='upload_view'),
    path('folder-upload.html', folderupload_page_view, name='folderupload_view'),
    path('verify-otp.html', verify_otp_view, name='verify_otp_view'),
    path('logout/', logout_view, name='logout'),
    path('forgot-password.html', forgot_password_view, name='forgot_password_view'),

    # OTP, Verify OTP, Forgot Password (Class-based views)
    path('request-otp/', OTPRequestView.as_view(), name='request-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),

    # Excel handling
    path('upload_excel/', upload_excel, name='upload_excel'),
    path('excel.html', excel_upload_page_view, name='excel_upload_view'),
    path('download_excel/', download_excel, name='download_excel'),
    
    # Search PO number
    path('search/', search_po_or_invoice_number, name='search_po_or_invoice_number'),
    
]