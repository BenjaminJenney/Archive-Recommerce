'''Reference for google auth: https://developers.google.com/identity/protocols/oauth2/web-server
    any other reference for this process in google's documentation is outdated
    google now uses it's own authentication libraries and not third party libs like Oauth
    So don't trust the top links that come up in a google search. 
'''

from email import message
import os
from re import search
from django.http.response import HttpResponse
from django.shortcuts import render
from django.shortcuts import redirect
from django.core import files

import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import httplib2
import email
import base64
from bs4 import BeautifulSoup, SoupStrainer
import pprint
import quopri
import html
from urllib import parse
from nltk.corpus import wordnet, stopwords
from nltk import word_tokenize
from nltk.util import ngrams
from read_email.models import User, ClosetItem, Closet
import re
from io import BytesIO
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image
# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'
REDIRECT_URI = 'http://localhost:8000/oauth2callback'
TARGET_BRANDS = ['acne studio', 'miranda', 'lilo', 'lille', 'nora', 'judith', 'chocolat', 'urbanita', 'high']
STOP_WORDS = ['address', 'delivery', 'exchange', 'what', 'that', 'chat']
def get_hyponyms(word):
    syn = wordnet.synsets(word)[0]
    hypos = lambda s:s.hyponyms()
    closure = syn.closure(hypos)
    return [s.name().split('.')[0].lower() for s in closure 
            if s.name().split('.')[0].lower() != 'livery'
            and s.name().split('.')[0].lower() != 'black']
CLOTHING_HYPONYMS = get_hyponyms('clothing')
for cloth in CLOTHING_HYPONYMS:
    if cloth in 'jeans miranda':
        print('cloth:', cloth)
CLOTHING_HYPONYMS.append('shorts')
CLOTHING_HYPONYMS.append('legwarmers')
CLOTHING_HYPONYMS.append('leg-warmers')
CLOTHING_HYPONYMS.append('short')
CLOTHING_HYPONYMS.append('loafers')
VENDORS = ['saks fifth avenue', 'h&m', 'net-a-porter', 'mango']
credentials_obj = None

####HELPERS#####

def simulate_browser(url):
    # Instantiate an Options object
# and add the "--headless" argument
    #opts = Options()
    #opts.add_argument(" --headless")
    #opts.add_argument('User-Agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36"')
    #opts.add_argument('Accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"')
    #opts.add_argument('Accept-Language="en-US,en;q=0.9"') . 
    # Instantiate a webdriver
    browser = webdriver.Chrome(ChromeDriverManager().install())
    browser.get(url)
    browser.execute_script("return document.getElementsByTagName('html')[0].innerHTML")
    return browser

def write_to_file(text):
    f = open('html.txt', 'w')
    f.writelines(text)
    f.close()

def is_price(text):
    if re.search('(\d+\.\d+)', text):
        return True
    return False

def get_date_from_snippet(snippet):
    date_str = snippet[snippet.find('Date:')+11:]
    date_str = date_str[:date_str.find('at')]
    #print('Date:', date_str)
    return date_str

def get_source_site_from_snippet(snippet):
    source_site = snippet[snippet.find('@'): snippet.find('>')]
    if source_site.count('.') > 1:
        source_site = source_site[source_site.find('.')+1:]
    #print(source_site)
    return source_site

def get_price(text):
    return re.search('(\d+\.\d+)', text).group(0) 

def clean_string(html_text):
    html_text = html_text.replace('=','')
    return html.unescape(html_text)

def clean_html(html_text):
    html_text = html_text.replace('\r\n','')
    html_text = html_text.replace('<=', '<')
    html_text = html_text.replace('that', '')
    
    return html_text

def make_ordered_set(list_):
    return list(dict.fromkeys(list_))

CLOTHING_HYPONYMS = make_ordered_set(CLOTHING_HYPONYMS)

def tokenize(text):
    text.replace('&', '')
    return word_tokenize(text.lower())

def add_to_db(user_attribs, closet_item_attribs):
    
    if (not User.objects.filter(name=user_attribs['name']).exists()): # If google user does not exist in the DB, update the DB,
        user_entry = User(name=user_attribs['name'], email=user_attribs['email'])
        user_entry.save()
    else: # Else delete and add fresh
        User.objects.get(name=user_attribs['name']).delete()
        user_entry = User(name=user_attribs['name'], email=user_attribs['email'])
        user_entry.save() 
    for i in range(len(closet_item_attribs['item_names'])):
        closet_item = ClosetItem(
            item_name = closet_item_attribs['item_names'][i],
            brand = closet_item_attribs['brands'][i],
            purchase_price = closet_item_attribs['purchase_prices'][i],
            vendor = closet_item_attribs['vendor'],
            purchased_date = closet_item_attribs['purchased_date'],
            source_site = closet_item_attribs['source_site']
            #image = closet_item_attribs['image_files'][i]
        )
        if len(closet_item_attribs['image_names']) > 0 or len(closet_item_attribs['image_files'])>0:
            closet_item.image.save(closet_item_attribs['image_names'][i] ,closet_item_attribs['image_files'][i])
        closet_item.save()
        closet = Closet(user=user_entry, closet_item=closet_item)
        closet.save()

def n_grams(text, n):
    n_grams = ngrams(tokenize(text), n)
    return [' '.join(grams) for grams in n_grams]

def get_urls_from_html(html_text): 
    soup = BeautifulSoup(html_text, 'html.parser')
    embedded_links = []
    for link in soup.find_all('a'):
        embedded_links.append(link.get('href'))
    return embedded_links

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def has_stopword(s):
    for stopword in STOP_WORDS:
        if stopword in s.lower():
            return True
    return False

def has_clothingword(s):
    for w in CLOTHING_HYPONYMS:
        if w in s:
            return True
    return False

def has_itemword(s,item_tkns):
    hasitemword = False 
    for item_tkn in item_tkns:
        for w in item_tkn:
            if w != '&':
                if w.lower() in s.lower():
                    #print('w:',w,'s:',s)
                    hasitemword = True
    print(hasitemword)
    return hasitemword

def decode_html(html_txt):
    html_txt = base64.urlsafe_b64decode(html_txt) 
    html_txt = quopri.decodestring(html_txt).decode('iso-8859-1')
    html_txt = clean_html(html_txt)
    return html_txt
    
def search_messages(service, user_id, search_string):
    search_id = service.users().messages().list(userId=user_id, q=search_string).execute()
    #print('list response: ', search_id)
    number_results = search_id['resultSizeEstimate']
    if number_results > 0:
        message_ids = search_id['messages']
        final_list  = []
        for ids in message_ids:
            final_list.append(ids['id'])
        return final_list
    else:
        print('There were 0 results for that search string, returning an empty string')
        return ''

def scrape_product_images(soup, product_links):
    #scrape data from product links from vendor
    product_image_filenames = []
    product_image_files = []

    for link_tag in soup.find_all('a'):
        #print('link_tag:', link_tag)
        for prod_link in product_links:
            #print('lt:',link_tag['href'])
            #print('pl:', prod_link)
            if link_tag['href'] == prod_link:
                img_tag = link_tag.find('img')
                if img_tag:
                    img_src = img_tag['src']
                    if img_src[0] != 'h':
                        img_src = 'https:' + img_src
                    #print('img_src',img_src)
                    response = requests.get(img_src)
                    #print('resstatus:', response.status_code)
                    if response.status_code != requests.codes.ok:
                        print('bad response on img_src')
                    else:
                        fp = BytesIO()
                        try:
                            Image.open(BytesIO(response.content))
                        except OSError:
                            print('Not a valid image')
                        fp.write(response.content)
                        product_image_filename = img_src.split("/")[-1]
                        product_image_file = files.File(fp)
                        product_image_files.append(product_image_file)
                        product_image_filenames.append(product_image_filename)
    return product_image_files, product_image_filenames
        ##print('resContent:', res.content)
        ##html_from_product_link = res.content
        #html_from_product_link = simulate_browser(prod_link)
        ##html_from_product_link = decode_html(html_from_product_link)
        #print('htmlfromProductlink', html_from_product_link)
        #prod_soup = BeautifulSoup(html_from_product_link, "html.parser")
        #write_to_file(str(prod_soup.prettify()))
        

def decode_message(service, user_id, msg_ids, user_info):
    text_parts = []
    
    for msg_id in msg_ids:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
#        message_full = service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
        #pprint.pp(message_full)
        snippet = html.unescape(message['snippet'])
        #print('snippet:',snippet)
        
        msg_byte = base64.urlsafe_b64decode(message['raw'].encode('utf-8'))
        
        msg_str = email.message_from_bytes(msg_byte)
        content_types = msg_str.get_content_maintype()
        
        if content_types == 'multipart':
            plain_text, html_text = msg_str.get_payload()
            plain_text = plain_text.get_payload()
            html_text  = html_text.get_payload()
            html_text  = quopri.decodestring(html_text).decode('iso-8859-1')
            scrape_brand_item_price(snippet, html_text, user_info)
        else:
            #print('msg:', msg_str.get_payload())
            text_parts.append(msg_str.get_payload())

def scrape_brand_item_price(html_snippet, html_text, user_info):
    
    purchase_prices = []
    brands = []
    items  = []
    product_links  = []
    vendor = ''
    product_image_file = ''
    product_image_filename = ''
    html_text = clean_html(html_text)
    soup = BeautifulSoup(html_text, 'html.parser')
    purchased_date = get_date_from_snippet(html_snippet)
    source_site = get_source_site_from_snippet(html_snippet)
    for p in soup('p'):
        p.decompose()

    item_tkns = []

    for string in soup.stripped_strings:
        string = clean_string(str(string))
        
        if len(string) > 60 or has_stopword(string):
            continue
    
        for item in CLOTHING_HYPONYMS:
            if item in string.lower():
                items.append(string)
                continue
         
        if is_price(string) and len(purchase_prices) < len(items):
            purchase_prices.append(get_price(string))

        for brand in TARGET_BRANDS:
            if brand in string.lower() and len(brands) < len(items):
                brands.append(brand)
        if not vendor:
            for vend in VENDORS:
                if vend in string.lower():
                    vendor = vend
        
    #items = make_ordered_set(items)
    #purchase_prices = make_ordered_set(purchase_prices)
    #brands = make_ordered_set(brands)
    #print(items)
    # get links for products in emails
    for link_tag in soup.find_all('a'):
        link_text = link_tag.string
        if link_text:
            if not has_stopword(link_text.lower()):
                if has_clothingword(link_text.lower()):
                    product_links.append(link_tag['href'])
    #print('prodlinks:', product_links)

    product_image_files, product_image_filenames = scrape_product_images(soup, product_links)
    header = { # Do not delete, might be useful later if you need to spoof a web browser.
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        }
    make_ordered_set(product_image_files)
    make_ordered_set(product_image_filenames)
    #print(res.content)
    if len(brands) == 0:
        for i in range(len(items)):
            brands.append('select a brand')
    user_attribs = {
        'name' : user_info['name'],
        'email' : user_info['email']
    }
    closet_item_attribs = {
        'item_names' : items,
        'vendor' : vendor,
        'purchase_prices': purchase_prices,
        'purchased_date': purchased_date,
        'source_site' : source_site,
        'brands' : brands,
        'image_names' : product_image_filenames,
        'image_files' : product_image_files
    }
    #print('brands: ', brands)
    #print('items:', items)
    #print('prices:', prices)
    pprint.pp(closet_item_attribs)
    add_to_db(user_attribs, closet_item_attribs)
#############################################################

####VIEWS#####

def test_api_request_view(request):
    if 'credentials' not in request.session:
        return redirect('authorize/')
      # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
      **request.session['credentials'])


    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials 
    ) # Use service object to do things with emails
    
    # Get user info: name, email, etc.
    user_info = requests.get(
        'https://www.googleapis.com/oauth2/v2/userinfo', 
        headers={'Authorization':'Bearer ' + credentials.token}).json() # json() Makes dict from json
    #add_user_to_db(user_info) # add user record to DB
    #print('userinfo:',user_info)
    saks_subj =  'subject:Thank You for Your Order #287529239'
    mango_subj = 'subject:Thank you for shopping at MANGO' 
    net_a_porter_subj = 'subject: Your NET-A-PORTER order confirmation'
    handm_subj = 'subject: H&M Order Confirmation'
    thnks_subj = 'subject:Thank You'
    uniqlo_subj = 'subject:Your UNIQLO order has shipped!'
    all_receipts = 'category:purchases | subject:your order '
    message_ids = search_messages(service, 'me', all_receipts)
    #print('len(msg_ids', len(message_ids))
    User.objects.all().delete()
    ClosetItem.objects.all().delete()
    Closet.objects.all().delete()
    decode_message(service, 'me', message_ids, user_info)
    return HttpResponse('msgs[0]')

def authorize_view(request):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES 
    )
    flow.redirect_uri = REDIRECT_URI

    authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')
    
    request.session['state'] = state
    return redirect(authorization_url)

def oauth2callback_view(request):
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = request.session['state']
    
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI

    authorization_response = request.build_absolute_uri()
    #print('authorization response')
    #pprint.pp(authorization_response)

    temp_var = request.build_absolute_uri()
    if "http:" in temp_var:
        temp_var = "https:" + temp_var[5:]
    
    flow.fetch_token(authorization_response=temp_var)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    # credentials in a persistent database instead.
    credentials = flow.credentials
    request.session['credentials'] = credentials_to_dict(credentials)
    return redirect('closet')

def home(request):
    return render(request, '../templates/home_page.html', {})

def get_started(request):
    return render(request, '../templates/get_started.html', {})

def closet_view(request):
    closet_items = ClosetItem.objects.all()
    for item in closet_items:
        print(item.image)
    dict = {
        'closet_items': closet_items
    }
    return render(request, '../templates/closet.html', dict)

def add_closet_view(request):
    return render(request, '../templates/add_to_closet.html', {})

# def get_started(request):
#     return render(request, 'read_email/get_started.html', {})

# def login(request):
#     return render(request, 'read_email/login.html', {})