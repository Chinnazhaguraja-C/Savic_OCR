 
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, HttpResponseNotAllowed
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.views.decorators.cache import never_cache
from rest_framework import generics, status
from rest_framework.views import APIView
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient
import os
import requests
import base64
import json
from .models import Invoice
from .serializers import UserSerializer, InvoiceSerializer
 
 
# Define your Azure Form Recognizer configuration
endpoint = "https://savic-ocr-integration-document-intelligence.cognitiveservices.azure.com/"
key = "7be7b9df5d014fbd94c2d5ce7961925a"
model_id = "Almaya_Choithram_Shankar_Trading_Custom_Model"
desired_fields = [
    'Invoice Number', 'Invoice Date', 'Purchase Order Number', 'VendorName', 'VendorAddress',
    'Vendor Tax Id', 'Customer Name', 'Customer Tax Id', 'SubTotal', 'Total Tax', 'Invoice Total',
    'Description', 'ProductCode', 'Barcode', 'Quantity', 'Tax', 'TaxRate', 'Unit',
    'UnitPrice','MaterialNumber','LineText','LineItemNo','Amount'
]
 
def extract_fields(result):
    data = []
    for idx, document in enumerate(result.documents):
        doc_data = flatten_document_fields(document.fields)
        data.append(doc_data)
    return data
 
def flatten_document_fields(fields):
    flattened_fields = {}
    for name, field in fields.items():
        field_value = field.value if field.value else field.content
        if name == 'Items' and field.value_type == "list":
            items_data = []
            for item in field.value:
                item_fields = flatten_document_fields(item.value)
                items_data.append(item_fields)
            flattened_fields[name] = items_data
        elif field.value_type == "dictionary":
            nested_flattened_fields = flatten_document_fields(field.value)
            flattened_fields.update(nested_flattened_fields)
        elif name in desired_fields:
            flattened_fields[name] = field_value
    return flattened_fields
 
def analyze_layout(file_path):
    document_analysis_client = DocumentAnalysisClient(
        endpoint=endpoint, credential=AzureKeyCredential(key)
    )
    with open(file_path, "rb") as file:
        content = file.read()
    poller = document_analysis_client.begin_analyze_document(
        model_id=model_id, document=content
    )
    result = poller.result()
    structured_output = extract_fields(result)
    return structured_output
 
def upload_invoice(request):
    if request.method == 'POST' and request.FILES.getlist('invoice'):
        invoice_files = request.FILES.getlist('invoice')
        combined_data = []
 
        for invoice_file in invoice_files:
            temp_file_path = os.path.join(settings.MEDIA_ROOT, 'temp_invoice.pdf')
            with open(temp_file_path, 'wb') as f:
                for chunk in invoice_file.chunks():
                    f.write(chunk)
 
            try:
                extracted_data = analyze_layout(temp_file_path)
                combined_data.append({
                    'invoice_name': invoice_file.name,
                    'extracted_data': extracted_data
                })
            except Exception as e:
                print(f"Error occurred during document analysis: {e}")
                return HttpResponse("Error occurred during document analysis.", status=500)
            finally:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
 
        context = {
            'combined_data': combined_data
        }
        return render(request, 'invoice_data.html', context)
    return render(request, 'upload.html')
 
 
 
def push_to_sap(request):
    if request.method == 'POST':
        data = json.loads(request.body)
       
        db_data = data.get('dbData', {})
        sap_data = data.get('sapData', {})
 
        json_data = json.dumps(data, indent=4)
        print("Received JSON data:", json_data)  # Print received JSON data to console
 
        username = "SAIP"
        password = "Praneeth@10"
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        sap_url = f"http://savic1909.savictech.com:8000/sap/bc/abap/zmigo_vk/rest/?sap-client=220&req={json.dumps(sap_data)}"
 
        response = requests.get(sap_url, headers={'Authorization': 'Basic ' + credentials})
        user = request.user  # Assuming you have user authentication set up
 
        if response.status_code == 200:
            sap_response_json = response.json()
            print("Response:", json.dumps(sap_response_json, indent=4))  # Print SAP response JSON to console
 
            if sap_response_json.get('code') == "Success:":
                message = 'Records :0008 got updated'
                invoice = Invoice(
                    user=user,
                    invoice_number=db_data.get('invoice_number', ''),
                    purchase_order_number=db_data.get('purchase_order_number', ''),
                    vendor_name=db_data.get('vendor_name', ''),
                    code="Success",
                    msgtxt=message
                )
                invoice.save()
 
                print(f'code: "Success:", msgtxt: "{message}"')
                return JsonResponse({'status': 'success', 'message': message})
            else:
                error_message = sap_response_json.get("msgtxt", "Unknown error")
                invoice = Invoice(
                    user=user,
                    invoice_number=db_data.get('invoice_number', ''),
                    purchase_order_number=db_data.get('purchase_order_number', ''),
                    vendor_name=db_data.get('vendor_name', ''),
                    code="Error",
                    msgtxt=error_message
                )
                invoice.save()
 
                print(f'code: "Error", msgtxt: "{error_message}"')
                return JsonResponse({'status': 'error', 'message': error_message}, status=response.status_code)
        else:
            error_message = f"Failed with status code: {response.status_code}"
            invoice = Invoice(
                user=user,
                invoice_number=db_data.get('invoice_number', ''),
                purchase_order_number=db_data.get('purchase_order_number', ''),
                vendor_name=db_data.get('vendor_name', ''),
                code="Error",
                msgtxt=error_message
            )
            invoice.save()
 
            print(f'code: "Error", msgtxt: "{error_message}"')
            return JsonResponse({'status': 'error', 'message': error_message}, status=response.status_code)
 
    return JsonResponse({'error': 'Method not allowed'}, status=405)
 
 
def home_page_view(request):
    return render(request, 'Home-page.html')
 
def verify_otp_view(request):
    return render(request, 'verify-otp.html')
 
def forgot_password_view(request):
    return render(request, 'forgot-password.html')
 
def reset_password_view(request):
    return render(request, 'reset-password.html')
 
def register_page_view(request):
    return render(request, 'register.html')
@login_required
def upload_page_view(request):
    return render(request, 'upload.html')
 
@login_required
def folderupload_page_view(request):
    return render(request, 'folder-upload.html')
 
class UserRegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=status.HTTP_201_CREATED)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
@ensure_csrf_cookie
def login_view(request):
    error_message = {'username': None, 'password': None}  # Initialize error messages
   
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect to drop-menu.html upon successful login
            return redirect('drop_menu')
        else:
            error_message['username'] = 'Invalid username or password'
            error_message['password'] = 'Invalid username or password'
 
    csrf_token = get_token(request)
    return render(request, 'login.html', {'error_message': error_message, 'csrf_token': csrf_token})
 
class InvoiceCreateView(generics.CreateAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
 
import json
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import render
from .models import Invoice
 
@login_required
def drop_menu_view(request):
    user = request.user  # Get the current logged-in user
 
    # Count of success and failed invoices
    success_count = Invoice.objects.filter(user=user, code='Success').count()
    failed_count = Invoice.objects.filter(user=user, code='Error').count()
    total_processed = success_count + failed_count  # Total processed invoices for the user
 
    # Fetch invoices for the user including invoice_number, purchase_order_number, and vendor_name, sorted by date in descending order
    invoices = Invoice.objects.filter(user=user).order_by('-date').values('invoice_number', 'purchase_order_number', 'vendor_name', 'code', 'date')
 
 
    # Aggregate data by date for the line charts
    invoices_by_date = Invoice.objects.filter(user=user).values('date').annotate(
        total_count=Count('id'),
        success_count=Count('id', filter=Q(code='Success')),
        failed_count=Count('id', filter=Q(code='Error'))
    ).order_by('date')
 
    dates = [entry['date'].strftime('%d-%m-%y') for entry in invoices_by_date]
    total_counts = [entry['total_count'] for entry in invoices_by_date]
    success_counts = [entry['success_count'] for entry in invoices_by_date]
    failed_counts = [entry['failed_count'] for entry in invoices_by_date]
 
    context = {
        'user': user,
        'success_count': success_count,
        'failed_count': failed_count,
        'total_processed': total_processed,
        'invoices': invoices,  # Pass the invoices queryset to the context
        'dates': json.dumps(dates),  # Encode as JSON string
        'total_counts': json.dumps(total_counts),  # Encode as JSON string
        'success_counts': json.dumps(success_counts),  # Encode as JSON string
        'failed_counts': json.dumps(failed_counts)  # Encode as JSON string
    }
 
    return render(request, 'drop-menu.html', context)
 
 
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.db.models import Q
 
from collections import defaultdict
from django.db.models import Count
 
def search_po_or_invoice_number(request):
    search_query = request.GET.get('search_query', '')
    if search_query:
        invoices = Invoice.objects.filter(
            Q(purchase_order_number__icontains=search_query) |
            Q(invoice_number__icontains=search_query) |
            Q(vendor_name__icontains=search_query)
        )
    else:
        invoices = Invoice.objects.all()
 
    # Aggregate data
    aggregated_data = invoices.values('date').annotate(
        success_count=Count('id', filter=Q(code='Success')),
        failed_count=Count('id', filter=Q(code='Error'))
    ).order_by('date')
 
    # Extract unique dates and counts
    dates = [data['date'] for data in aggregated_data]
    success_counts = [data['success_count'] for data in aggregated_data]
    failed_counts = [data['failed_count'] for data in aggregated_data]
 
    # Render the partial template to a string
    invoices_html = render_to_string('partials/invoice_table.html', {
        'invoices': invoices
    })
 
    return JsonResponse({
        'html': invoices_html,
        'search_query': search_query,
        'success_count': sum(success_counts),
        'failed_count': sum(failed_counts),
        'total_processed': len(invoices),
        'dates': dates,
        'success_counts': success_counts,
        'failed_counts': failed_counts
    })
 
 
 
 
@never_cache
def logout_view(request):
    logout(request)
    return redirect('login')  # Adjust this to your login URL name
 
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.hashers import check_password
from django.contrib import messages
from .forms import ResetPasswordForm
 
User = get_user_model()
 
def reset_password_view(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            current_password = form.cleaned_data['current_password']
            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']
 
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.')
                return render(request, 'reset-password.html')
 
            if not user.check_password(current_password):
                messages.error(request, 'Invalid current password.')
                return render(request, 'reset-password.html')
 
            if new_password != confirm_password:
                messages.error(request, 'New password and confirm password do not match.')
                return render(request, 'reset-password.html')
 
            user.set_password(new_password)
            user.save()
 
            # Update the user's session to reflect the password change
            update_session_auth_hash(request, user)
 
            messages.success(request, 'Password reset successful. Please log in with your new password.')
            return redirect('login')
    else:
        form = ResetPasswordForm()
 
    return render(request, 'reset-password.html', {'form': form})
 
 
# Forgot Password view
 
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.utils import timezone
from .serializers import OTPRequestSerializer
from .models import OTP
from .utils import send_otp_email, generate_otp
from datetime import timedelta
 
User = get_user_model()
 
class OTPRequestView(APIView):
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            otp = generate_otp()
            OTP.objects.create(user=user, otp=otp, expires_at=timezone.now() + timedelta(minutes=5))
            send_otp_email(email, otp)
            return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        entered_otp = request.data.get('otp')
       
        try:
            user = User.objects.get(email=email)
            otp_record = OTP.objects.filter(user=user, otp=entered_otp).last()
           
            if otp_record and otp_record.is_valid():
                return Response({"verified": True}, status=status.HTTP_200_OK)
            else:
                return Response({"verified": False}, status=status.HTTP_400_BAD_REQUEST)
       
        except User.DoesNotExist:
            return Response({"verified": False}, status=status.HTTP_400_BAD_REQUEST)
 
 
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny
 
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
 
    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
       
        if new_password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
       
        try:
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
       
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
       
@login_required      
def excel_upload_page_view(request):
    return render(request, 'excel.html')
 
 
import pandas as pd
import json
import base64
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
 
@csrf_exempt  # For demo purposes; use CSRF protection in production appropriately
def upload_excel(request):
    if request.method == 'POST':
        if 'excelFile' not in request.FILES:
            return JsonResponse({'error': 'No file part'}, status=400)
       
        file = request.FILES['excelFile']
       
        if file.name == '':
            return JsonResponse({'error': 'No selected file'}, status=400)
       
        try:
            # Read the Excel file into a DataFrame
            df = pd.read_excel(file)
 
            # Expected headers
            expected_headers = ['VEN_NAME', 'EBELN', 'TXZ01', 'MENGE_PO', 'MENGE_GR']
 
            # Check if the headers match
            if not all(header in df.columns for header in expected_headers):
                return JsonResponse({
                    'error': 'Invalid Excel headers. Please make sure the headers are: VEN_NAME, EBELN, TXZ01, MENGE_PO, MENGE_GR'
                }, status=400)
 
            # Convert DataFrame to a list of dictionaries
            records = df.to_dict(orient='records')
 
            # Format the data as required
            response_data = {
                "ID": "1001",
                "BODY": []
            }
           
            for record in records:
                body_entry = {
                    "VEN_NAME": record.get('VEN_NAME', ''),
                    "EBELN": record.get('EBELN', ''),
                    "TXZ01": record.get('TXZ01', ''),
                    "MENGE_PO": str(record.get('MENGE_PO', '')),
                    "MENGE_GR": record.get('MENGE_GR', '')
                }
                response_data["BODY"].append(body_entry)
 
            json_data = json.dumps(response_data, indent=4)
            print("Received JSON data:", json_data)
 
            # Example of SAP endpoint integration (consider using POST for sending data)
            username = "SAIP"
            password = "Praneeth@10"
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            sap_url = f"http://savic1909.savictech.com:8000/sap/bc/abap/zmigo_vk/rest/?sap-client=220&req={json.dumps(response_data)}"
 
            # Send data to SAP (consider using POST method here)
            response = requests.get(sap_url, headers={'Authorization': 'Basic ' + credentials})
 
            if response.status_code == 200:
                print("JSON data retrieved successfully from SAP portal!")
                sap_response_json = response.json()
                print("Response:", json.dumps(sap_response_json, indent=4))
            else:
                print("Failed to push JSON data to SAP portal. Status code:", response.status_code)
                print("Error message:", response.text)
                return JsonResponse({
                    'error': f"Failed to push JSON data to SAP portal. Status code: {response.status_code}, Error message: {response.text}"
                }, status=400)
 
            return JsonResponse(response_data, safe=False)
 
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
 
    return JsonResponse({'error': 'Invalid request method'}, status=405)
 
 
 
from django.conf import settings
 
def download_excel(request):
    # Generate a sample Excel file
    sample_data = {
        'VEN_NAME': [],
        'EBELN': [],
        'TXZ01': [],
        'MENGE_PO': [],
        'MENGE_GR': []
    }
    df = pd.DataFrame(sample_data)
 
    # Save the DataFrame to an Excel file
    file_path = os.path.join(settings.MEDIA_ROOT, 'sample.xlsx')
    df.to_excel(file_path, index=False)
 
    # Serve the file as a response
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="sample.xlsx"'
        return response
   
 