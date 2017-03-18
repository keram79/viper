# Standard Imports
import os
import re
import sys
import time

# Compression
import tarfile
from zipfile import ZipFile
from gzip import GzipFile
from bz2 import BZ2File

# Django Imports
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

# Viper imports
sys.path.append(settings.V_PATH)
from viper.core.session import __sessions__
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.common.objects import File
from viper.core.storage import store_sample, get_sample_path
from viper.core.database import Database
from viper.core.ui.commands import Commands
from viper.common.constants import VIPER_ROOT
from viper.common.autorun import autorun_module
from viper.core.config import Config

try:
    from scandir import walk
except ImportError:
    from os import walk
try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

# Logging
import logging

logger = logging.getLogger(__name__)
cfg = Config()


# Helper Functions
def open_db(project):
    # Check for valid project
    project_list = __project__.list()
    if any(d.get('name', None) == project for d in project_list):
        # Open Project
        __project__.open(project)
        # Init DB
        return Database()

def api_check(request):
    # If API Key is not required
    if not cfg.api.api_access_key_enabled:
        return True
    # Check for valid key
    else:
        if 'HTTP_AUTHORIZATION' in request.META:
            if cfg.api.api_access_key == request.META['HTTP_AUTHORIZATION']:
                return True

# Create your views here.
def main_page(request):
    # If nothing specified lets return a simple user guide.
    return render(request, 'api.html', {'sample_list': 'Blah'})


# Test Json
def test_page(request):
    if not api_check(request):
        return JsonResponse({'response': '403', 'data': 'Unauthorised API Key, Or Authorization header not set.'})
    return JsonResponse({'response': '200', 'data': 'test'})


# List Projects
def project_list(request):
    project_list = __project__.list()
    return JsonResponse({'response': '200', 'data': project_list}, safe=False)


# File View
def file_view(request, sha256, project):
    if not sha256:
        return JsonResponse({'response': '404', 'data': 'Requires a SHA256'})
    db = open_db(project)
    # Open a session
    try:
        path = get_sample_path(sha256)
        __sessions__.new(path)
    except:
        return JsonResponse({'response': '404', 'data': 'Unabel to access file'})

    # Get the file info
    file_info = {
        'name': __sessions__.current.file.name,
        'tags': __sessions__.current.file.tags.split(','),
        'path': __sessions__.current.file.path,
        'size': __sessions__.current.file.size,
        'type': __sessions__.current.file.type,
        'mime': __sessions__.current.file.mime,
        'md5': __sessions__.current.file.md5,
        'sha1': __sessions__.current.file.sha1,
        'sha256': __sessions__.current.file.sha256,
        'sha512': __sessions__.current.file.sha512,
        'ssdeep': __sessions__.current.file.ssdeep,
        'crc32': __sessions__.current.file.crc32,
        'parent': __sessions__.current.file.parent,
        'children': __sessions__.current.file.children.split(',')
    }

    # Get Any Notes
    note_list = []
    module_history = []
    malware = db.find(key='sha256', value=sha256)
    if malware:
        notes = malware[0].note
        if notes:
            for note in notes:
                note_list.append({'title': note.title,
                                  'body': note.body,
                                  'id': note.id
                                  })
        analysis_list = malware[0].analysis
        if analysis_list:
            for ana in analysis_list:
                module_history.append({'id': ana.id,
                                       'cmd_line': ana.cmd_line
                                       })

    # Return the page
    return JsonResponse({'response': '200', 'data': {'file_info': file_info,
                                                     'note_list': note_list,
                                                     'module_history': module_history
                                                     }})


# Tags
def tag_list(request, project):
    if not project:
        project = 'default'
    # Open DB on correct Project
    db = open_db(project)
    if db:
        rows = db.list_tags()
        results = []
        for row in rows:
            results.append(row.tag)
        return JsonResponse({'response': '200', 'data': results}, safe=False)
    else:
        return JsonResponse({'response': '404', 'data': 'Unable to find project'}, safe=False)


# Search
def search_file(request):
    key = request.POST['key']
    value = request.POST['term'].lower()
    curr_project = request.POST['curr_project']
    if 'project' in request.POST:
        project_search = request.POST['project']
    else:
        project_search = False

    # Set some data holders
    results = []
    projects = []

    # Search All Projects
    if project_search:
        # Get list of project paths
        project_list = __project__.list()
        for p in project_list:
            projects.append(p['name'])
    else:
        # If not searching all projects what are we searching
        projects.append(curr_project)

    # Search each Project in the list
    for project in projects:
        db = open_db(project)
        #get results
        proj_results = []
        rows = db.find(key=key, value=value)
        for row in rows:
            proj_results.append([row.name, row.sha256])
        results.append({'name':project, 'res':proj_results})
    # Return some things
    return JsonResponse({'response': '200', 'data': results}, safe=False)

# File Upload
def file_upload(request):
    # Add New File
    # Uses Context Manager to Remove Temp files
    # Lets start getting some options

    # Type should be set to url, vt or local
    # If not set assume local

    if 'upload_type' in request.POST:
        upload_type = request.POST['upload_type']
    else:
        upload_type = 'local'


    tags = request.POST['tag_list']
    if upload_type == 'local':
        uploads = request.FILES.getlist('file')
    elif upload_type == 'url':
        uploads = request.POST['files'].split(',')
    elif upload_type == 'vt':
        uploads = request.POST['files']
    else:
        return JsonResponse({'response': '500', 'data': 'You didnt specify anything to do'}, safe=False)


    compression = request.POST['compression']

    if 'storezip' in request.POST:
        store_zip = request.POST['storezip']
    else:
        store_zip = False

    # Set Project
    project = request.POST['project']
    if not project:
        project = 'default'
    db = open_db(project)

    # Write temp file to disk
    with upload_temp() as temp_dir:
        for upload in uploads:
            file_path = os.path.join(temp_dir, upload.name)
            with open(file_path, 'w') as tmp_file:
                tmp_file.write(upload.file.read())
            parent = None

            #  If not compressed or we want to store the zip as well.
            if compression == 'none' or store_zip:
                stored = add_file(file_path, tags, None)
                if store_zip:
                    parent = stored

            # Zip Files
            if compression == 'zip':
                print 'zip file'
                zip_pass = request.POST['zip_pass']
                try:
                    with ZipFile(file_path) as zf:
                        zf.extractall(temp_dir, pwd=zip_pass)
                    for root, dirs, files in walk(temp_dir, topdown=False):
                        for name in files:
                            print name
                            if not name == upload.name:
                                stored = add_file(os.path.join(root, name), tags, parent)
                                print stored
                except Exception as e:
                    error = "Error with zipfile - {0}".format(e)
                    print error

            # GZip Files
            elif compression == 'gz':
                try:
                    gzf = GzipFile(file_path, 'rb')
                    decompress = gzf.read()
                    gzf.close()
                    with open(file_path[:-3], "wb") as df:
                        df.write(decompress)
                    stored = add_file(file_path[:-3], tags, parent)
                except Exception as e:
                    error = "Error with gzipfile - {0}".format(e)

            # BZip2 Files
            elif compression == 'bz2':
                try:
                    bz2f = BZ2File(file_path, 'rb')
                    decompress = bz2f.read()
                    bz2f.close()
                    with open(file_path[:-3], "wb") as df:
                        df.write(decompress)
                    stored = add_file(file_path[:-3], tags, parent)
                except Exception as e:
                    return template('error.tpl', error="Error with bzip2file - {0}".format(e))

            # Tar Files (any, including tar.gz tar.bz2)
            elif compression == 'tar':
                try:
                    if not tarfile.is_tarfile(file_path):
                        return template('error.tpl', error="This is not a tar file")
                    with tarfile.open(file_path, 'r:*') as tarf:
                        tarf.extractall(temp_dir)
                    for root, dirs, files in walk(temp_dir, topdown=False):
                        for name in files:
                            if not name == upload.filename:
                                stored = add_file(os.path.join(root, name), tags, parent)
                except Exception as e:
                    error = "Error with tarfile - {0}".format(e)

                    # ToDo 7zip needs a sys call till i find a nice library

    return redirect("/project/{0}".format(project))