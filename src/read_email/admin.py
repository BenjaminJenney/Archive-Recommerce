from django.contrib import admin
from .models import User, ClosetItem, Closet

# Register your models here.

admin.site.register(User)
admin.site.register(ClosetItem)
admin.site.register(Closet)