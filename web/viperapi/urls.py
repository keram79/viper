from django.conf.urls import patterns, url
from viperapi import views

urlpatterns = patterns('',
    # Main Page
    url(r'^$', views.main_page, name='main_page'),

    # Test Page
    url(r'^test$', views.test_page, name='test_page'),

    # Project List
    url(r'^project/list$', views.project_list, name='project_list'),

    # Tags
    url(r'tags/list(?:/(?P<project>.+))?/$', views.tag_list, name='tag_list'),

    # File Details
    url(r'^file/(?P<project>.+)/(?P<sha256>.+)/$', views.file_view, name='file_view'),

    # File Upload
    url(r'^upload/$', views.file_upload, name='file_upload'),

    # Search
    url(r'^search/$', views.search_file, name='search_file'),

)
