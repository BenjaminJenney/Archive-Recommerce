# from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.shortcuts import render
from .forms import SignUpForm, UserCreationForm


class SignUpView(generic.CreateView):
    form_class = UserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'

# def signup(request):
#     form = SignUpForm(request.POST)
#     if form.is_valid:
#         pass
#     else:
#         form = SignUpForm()

#     context = {
#         "form": form
#     }
#     return render(request, "registration/signup.html", context)

