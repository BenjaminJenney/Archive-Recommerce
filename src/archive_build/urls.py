"""archive_build URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings

#from read_email.views import authorize_view, oauth2callback_view, test_api_request_view
from django.views.generic.base import TemplateView
from read_email.views import authorize_view, oauth2callback_view, test_api_request_view, closet_view
from pages.views import home, get_started, third_party_signin_view
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('get-started/', get_started, name='get-started'),
    path('closet/', closet_view, name='closet'),
    # path('third_party_signin/', third_party_signin_view, name='tparty_signin'),
    # path('get-started/', TemplateView.as_view(template_name='get.html'), name='home'),
    path('accounts/', include('accounts.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('authorize/', authorize_view),
    path('oauth2callback/', oauth2callback_view),
    path('test/', test_api_request_view, name='test')
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
