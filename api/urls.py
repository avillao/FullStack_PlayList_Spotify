from django.urls import path
from api.views import CallbackSpotify, ConnectView, InitSearchTracks, Login, Playlist, RefreshToken

urlpatterns = [
    path('auth/login/', Login.as_view() ),
    path('auth/callback/',CallbackSpotify.as_view()),
    path('auth/connect/<str:clave>',ConnectView.as_view()),
    path('initTrack/search',InitSearchTracks.as_view()),
    path('playlist/create/',Playlist.as_view(),name='playlist'),
    path('auth/refreshToken',RefreshToken.as_view()),
    
]