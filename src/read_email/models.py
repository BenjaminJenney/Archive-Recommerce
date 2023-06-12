from django.db import models
from django.db.models.fields.related import ForeignKey
from django.conf import settings
import os


    
# Create your models here.
class ClosetItem(models.Model):
    item_name = models.CharField(max_length=50)
    vendor = models.CharField(max_length=50)
    purchase_price = models.DecimalField(max_digits=6, decimal_places=2)
    purchased_date = models.CharField(max_length=20)
    source_site = models.URLField(max_length=200)
    brand = models.CharField(max_length=100, null=True)
    image = models.ImageField(upload_to='imgs',null=True, blank=True)
    
class User(models.Model):
    name  = models.CharField(max_length=50)
    email = models.EmailField(max_length=254)
    #closet_item = models.ForeignKey(ClosetItem, on_delete=models.CASCADE)

class Closet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    closet_item = models.ForeignKey(to=ClosetItem, on_delete=models.CASCADE)
    
