from datetime import datetime
from os import stat
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response
import requests
import spotipy
import base64

from rest_framework import status

from spotipy.oauth2 import RequestHandler
from playlist.settings import SPOTIFY_SCOPE,SPOTIFY_CLIENT_ID,SPOTIFY_CLIENT_SECRET,SPOTIFY_REDIRECT_URI

auth_manager = spotipy.oauth2.SpotifyOAuth(client_id=SPOTIFY_CLIENT_ID,client_secret=SPOTIFY_CLIENT_SECRET, redirect_uri=SPOTIFY_REDIRECT_URI,scope=SPOTIFY_SCOPE,show_dialog=True)

class Login(APIView):
    def get(self,request):        
        url = auth_manager.get_authorize_url()    
        return Response(url)
    
    
class CallbackSpotify(APIView):
    def get(self,request):
        if request.GET.get("code"):
            token = auth_manager.get_access_token(request.GET.get("code"))
            max_age = int(token['expires_in']) - 10
            response = HttpResponseRedirect(redirect_to='http://localhost:4200/home')
            response.set_cookie("AccessToken",token["access_token"],max_age=60)
            response.set_cookie("RefreshToken",token["refresh_token"],max_age=18000)
            return response
        return Response({"error":"Code param not provided"},status=status.HTTP_400_BAD_REQUEST)
    
class RefreshToken(APIView):
    def get(self,request):
        print("Refrescando token")
        
        if request.GET.get("token"):
            response = HttpResponse()
            token = auth_manager.refresh_access_token(request.GET.get("token"))
            max_age = int(token["expires_in"]) - 10
            response.set_cookie("AccessToken",token["access_token"],max_age=max_age)
            return response
        
        return Response({"error":"Token not provided"},status=status.HTTP_400_BAD_REQUEST)

class InitSearchTracks(APIView):
    
    def get(self,request):
        if request.GET.get("word") and request.GET.get("token"):
            print("buscando")
            token = request.GET.get("token")
            word = request.GET.get("word").lstrip()
            
            sp = spotipy.Spotify(auth=token,auth_manager=auth_manager)
        
            list_ids = []

            for letter in word:
                
                offset = 0
                total = 1000
                flag = True
                
                while flag: 
                    if offset >= total:
                        list_ids.append('')
                        break
                    
                    results = sp.search(q="genre:blues track:"+letter,type="track",limit=50,offset=offset)
                    
                    if offset == 0:
                        total = results['tracks']['total']
                    
                    for item in results['tracks']['items']:
                        if item['name'].startswith(letter.upper()):
                            if item['id'] not in list_ids:
                                list_ids.append(item['id'])
                                flag = False
                                break
                    
                    offset += 50
            
            return Response({"tracks":list_ids})
        
        return Response({"error":"Access Token o Word no son proveidos"},status=status.HTTP_400_BAD_REQUEST)
    
class Playlist(APIView):
    
    #auth_manager=spotipy.oauth2.SpotifyOAuth(client_id=SPOTIFY_CLIENT_ID,client_secret=SPOTIFY_CLIENT_SECRET, redirect_uri=SPOTIFY_REDIRECT_URI,scope=SPOTIFY_SCOPE,show_dialog=True)
    token = ''
    
    def get(self,request):
        auth_string:str = SPOTIFY_CLIENT_ID+":"+SPOTIFY_CLIENT_SECRET
        code = request.GET['code']
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic '+ base64.b64encode(auth_string.encode('ascii')).decode("ascii")
        }
        body = {
            "grant_type" : "authorization_code",
            "code":code,
            "redirect_uri": SPOTIFY_REDIRECT_URI
        }
        
        response = requests.post("https://accounts.spotify.com/api/token",headers=headers,json=body).json()
        if response.get('error'):
            token = None
        else:
            token = response.get('access_token')
        return redirect(reverse('playlist'))
    
    def post(self,request):
        
        print(self.auth_manager.get_authorization_code())
        #SpotifyAuth.SpotifyAuthenticateFlow()
        
        #sp.user_playlist_create(user=SPOTIFY_CLIENT_ID,name=request.data.get("word"),public=False,collaborative=False,description="Any description")
        
        return Response({"msg":"Se creó con éxito la playlist"})
    

class ConnectView(APIView):
    
    def get(self,request,clave):
        if not request.session.get("key",False):
            key = Fernet.generate_key()
            request.session["key"] = key.decode("utf-8") 
        
        public_key = serialization.load_pem_public_key(base64.b64decode(clave.encode()))
        cipher_key = public_key.encrypt(
            request.session["key"].encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return Response(base64.b64encode(cipher_key).decode())