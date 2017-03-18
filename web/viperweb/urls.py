from django.conf.urls import patterns, url

from viperweb import views

urlpatterns = patterns('',
    # Main Page
    url(r'^$', views.main_page, name='main_page'),
    url(r'project/(?P<project>.+)/$', views.main_page, name='main_page'),
   
    # Login Page
    url(r'^login/', views.login_page, name='login'),
    
    # Logout Page
    url(r'^logout/', views.logout_page, name='logout'),
    
    # File Page
    url(r'^file/(?P<project>.+)/(?P<sha256>.+)/$', views.file_view, name='file_view'),
    
    # Hex
    url(r'^hex/$', views.hex_view, name='hex_view'),
    
    # Module Ajax
    url(r'^module/$', views.run_module, name='run_module'),
    
    # Yara
    url(r'^yara/$', views.yara_rules, name='yara_rules'),

    # Create Project
    url(r'^create/$', views.create_project, name='create_project'),

    # Upload File
    url(r'^upload/$', views.upload_files, name='upload_files'),

    # Upload from URL
    url(r'urldownload/', views.url_download, name='url_download'),

    # Config File
    url(r'^config/$', views.config_file, name='config_file'),

    # Search
    url(r'^search/$', views.search_file, name='search_file'),
)
