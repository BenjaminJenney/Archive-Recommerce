from django.shortcuts import render

# Create your views here.
def home(request):
    return render(request, '../templates/home_page.html', {})

def get_started(request):
    return render(request, '../templates/get_started.html', {})

def third_party_signin_view(request):
    return render(request, '../templates/third_party_signin.html', {})