# Standard Imports
import os
import re
import sys
import json
import tempfile
import contextlib
import shutil

# Compression
import tarfile
from zipfile import ZipFile
from gzip import GzipFile
from bz2 import BZ2File

# Django Imports
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
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
from viper.common import network
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

# Create your views here.

##
# Helper Functions
##

# Module Dicts
mod_dict = {'apk': {'help': '-h', 'info': '-i', 'perm': '-p', 'list': '-f', 'all': '-a', 'dump': '-d'},
            'clamav': {'run': ''},
            'debup': {'info': '', 'extract': '-s'},
            'editdistance': {'run': ''},
            'elf': {'sections': '--sections', 'segments': '--segments', 'symbols': '--symbols',
                    'interp': '--interpreter', 'dynamic': '--dynamic'},
            'email': {'envelope': '-e', 'attach': '-f', 'header': '-r', 'trace': '-t', 'traceall': '-T', 'spoof': '-s',
                      'all': '-a'},
            'exif': {'run': ''},
            'fuzzy': {'run': ''},
            'html': {'scripts': '-s', 'links': '-l', 'iframe': '-f', 'embed': '-e', 'images': '-i', 'dump': '-d'},
            'idx': {'run': ''},
            'image': {'ghiro': '--ghiro'},
            'jar': {'run': ''},
            'office': {'meta': '-m', 'oleid': '-o', 'streams': '-s', 'export': '-e'},
            'pdf': {'id': 'id', 'streams': 'streams'},
            'pe': {'imports': 'imports', 'exports': 'exports', 'res': 'resources', 'imp': 'imphash',
                   'compile': 'compiletime',
                   'peid': 'peid', 'security': 'security', 'language': 'language', 'sections': 'sections',
                   'pehash': 'pehash'},
            'rat': {'auto': '-a', 'list': '-l'},
            'reports': {'malwr': '--malwr', 'anubis': '--anubis', 'threat': '--threat', 'joe': '--joe',
                        'meta': '--meta'},
            'shellcode': {'run': ''},
            'strings': {'all': '-a', 'hosts': '-H'},
            'swf': {'decom': 'decompress'},
            'virustotal': {'scan': '', 'submit': '-s'},
            'xor': {'xor': '', 'rot': '-r', 'all': '-a', 'export': '-o'},
            'yara': {'scan': 'scan -t', 'all': 'scan -a -t'}
            }


# context manager for file uploader
@contextlib.contextmanager
def upload_temp():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def open_db(project):
    project_list = __project__.list()
    # Check for valid project
    if project == 'default':
        __project__.open(project)
    elif any(d.get('name', None) == project for d in project_list):
        # Open Project
        __project__.open(project)
    else:
        return False
    return Database()


def project_list():
    # Get a list of projects 
    projects_path = os.path.join(VIPER_ROOT, 'projects')
    p_list = []
    if os.path.exists(projects_path):
        for project in os.listdir(projects_path):
            project_path = os.path.join(projects_path, project)
            if os.path.isdir(project_path):
                p_list.append(project)
    return p_list


def print_output(output):
    if not output:
        return '<p class="text-danger">! The command Generated no Output</p>'
    return_html = ''
    for entry in output:
        # Skip lines that say seesion opened
        if 'Session opened on' in entry['data']:
            continue
        if entry['type'] == 'info':
            return_html += '<p class="text-primary">{0}</p>'.format(entry['data'])
            # self.log('info', entry['data'])
        elif entry['type'] == 'item':
            return_html += '<li class="text-primary">{0}</li>'.format(entry['data'])
        elif entry['type'] == 'warning':
            return_html += '<p class="text-warning">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'error':
            return_html += '<p class="text-danger">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'success':
            return_html += '<p class="text-success">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'table':
            # set the table
            return_html += '<table class="table table-bordered">'
            # Column Titles
            return_html += '<tr>'
            for column in entry['data']['header']:
                return_html += '<th>{0}</th>'.format(column)
            return_html += '</tr>'
            # Rows
            for row in entry['data']['rows']:
                return_html += '<tr>'
                for cell in row:
                    return_html += '<td>{0}</td>'.format(cell)
                return_html += '</tr>'
            # Close table
            return_html += '</table>'
        else:
            return_html += '<p>{0}</p>'.format(entry['data'])
    return return_html


def parse(data):
    args = []
    # Split words by white space.
    words = data.split()
    # First word is the root command.
    root = words[0]
    # If there are more words, populate the arguments list.
    if len(words) > 1:
        args = words[1:]
    return root, args


def parse_text(module_text):
    # String to hold the new text
    set_text = ''
    # Split in to lines.
    for line in module_text.split('\n'):
        # Remove the colour codes
        line = re.sub('\[(\d)+m', '', line.replace('\x1b', ''))
        # Ignore the line that says we opened a session
        if 'Session opened on' in line:
            continue
        # add text the string
        set_text += '{0}\n'.format(line)
    return set_text


# this will allow complex command line parameters to be passed in via the web gui    
def module_cmdline(cmd_line, file_hash):
    html = ""
    cmd = Commands()
    split_commands = cmd_line.split(';')
    for split_command in split_commands:
        split_command = split_command.strip()
        if not split_command:
            continue
        root, args = parse(split_command)
        try:
            if root in cmd.commands:
                cmd.commands[root]['obj'](*args)
                html += print_output(cmd.output)
                del (cmd.output[:])
            elif root in __modules__:
                # if prev commands did not open a session open one on the current file
                if file_hash:
                    path = get_sample_path(file_hash)
                    __sessions__.new(path)
                module = __modules__[root]['obj']()
                module.set_commandline(args)
                module.run()

                html += print_output(module.output)
                if cfg.modules.store_output and __sessions__.is_set():
                    Database().add_analysis(file_hash, split_command, module.output)
                del (module.output[:])
            else:
                html += '<p class="text-danger">{0} is not a valid command</p>'.format(cmd_line)
        except Exception as e:
            html += '<p class="text-danger">We were unable to complete the command {0}</p>'.format(cmd_line)
    __sessions__.close()
    return html


def add_file(file_path, tags, parent):
    obj = File(file_path)
    new_path = store_sample(obj)
    print new_path
    success = True
    if new_path:
        # Add file to the database.
        db = Database()
        success = db.add(obj=obj, tags=tags, parent_sha=parent)

        # AutoRun Modules
        if cfg.autorun.enabled:
            autorun_module(obj.sha256)
            # Close the open session to keep the session table clean
            __sessions__.close()
        return obj.sha256

    else:
        # ToDo Remove the stored file if we cant write to DB
        return


##
# Views
##

# Login Page
def login_page(request):
    try:
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('/')
                else:
                    error = "This account has been disabled"
                    return main_page(request, project='default', error=error)
            else:
                error = "Unable to login to the Web Panel. Check your UserName and Password"
                return main_page(request, project='default', error=error)
    except:
        error = "Unable to login to the Web Panel"
        return main_page(request, project='default', error=error)


# Logout Page
def logout_page(request):
    logout(request)
    success = "You have been logged out"
    return main_page(request, project='default', success=success)


# Main Page
def main_page(request, project='default', error=None, success=None):
    db = open_db(project)

    # set pagination details
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 25

    # Get all Samples
    sample_list = db.find('all')

    sample_count = len(sample_list)
    first_sample = int(page) * int(page_count) - int(page_count) + 1
    last_sample = int(page) * int(page_count)
    paginator = Paginator(sample_list, page_count)
    try:
        samples = paginator.page(page)
    except PageNotAnInteger:
        samples = paginator.page(1)
    except EmptyPage:
        samples = paginator.page(paginator.num_pages)
    return render(request, 'index.html', {'sample_list': samples,
                                          'sample_count': sample_count,
                                          'samples': [first_sample, last_sample],
                                          'error_line': False,
                                          'project': project,
                                          'projects': __project__.list(),
                                          'error': error,
                                          'success':success
                                          })


# Add New File
# Uses Context Manager to Remove Temp files
@login_required
def upload_files(request):
    tags = request.POST['tag_list']
    uploads = request.FILES.getlist('file')
    compression = request.POST['compression']

    if 'storezip' in request.POST:
        store_zip = request.POST['storezip']
    else:
        store_zip = False

    # Set Project
    project = request.POST['project']
    if not project:
        project = 'default'
    open_db(project)

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
                    return main_page(request, project=project, error=error)

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
                    return main_page(request, project=project, error=error)

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
                    error = "Error with bzip2file - {0}".format(e)
                    return main_page(request, project=project, error=error)

            # Tar Files (any, including tar.gz tar.bz2)
            elif compression == 'tar':
                try:
                    if not tarfile.is_tarfile(file_path):
                        error = "This is not a tar file"
                        return redirect("/project/{0}".format(project))
                    with tarfile.open(file_path, 'r:*') as tarf:
                        tarf.extractall(temp_dir)
                    for root, dirs, files in walk(temp_dir, topdown=False):
                        for name in files:
                            if not name == upload.filename:
                                stored = add_file(os.path.join(root, name), tags, parent)
                except Exception as e:
                    error = "Error with tarfile - {0}".format(e)
                    return main_page(request, project=project, error=error)

                    # ToDo 7zip needs a sys call till i find a nice library

    return redirect("/project/{0}".format(project))


#add file from url
def url_download(request):
    url = request.POST['url']
    tags = request.POST['tag_list']
    tags = "url,"+tags
    project = request.POST['project']
    if 'tor' in request.POST:
        upload = network.download(url,tor=True)
    else:
        upload = network.download(url,tor=False)
    if upload is None:
        error = "server can't download from URL"
        return main_page(request, project=project, error=error)

    # Set Project
    project = request.POST['project']
    if not project:
        project = 'default'
    open_db(project)

    tf = tempfile.NamedTemporaryFile()
    tf.write(upload)
    if tf == None:
        error = "server can't download from URL"
        return main_page(request, project=project, error=error)
    tf.flush()

    sha_256 = add_file(tf.name, tags, None)
    if sha_256:
        return redirect("/project/{0}".format(project))
    else:
        error = "Unable to Store The File, already in database"
        return main_page(request, project=project, error=error)


# VirusTotal Download
def vt_download(request):
    vt_hash = request.POST['vt_hash']
    project = request.POST['project']
    tags = request.POST['tag_list']
    cmd_line = 'virustotal -d {0}; store; tags -a {1}'.format(vt_hash, tags)

    module_results = module_cmdline(cmd_line, False)

    if 'Stored' in module_results:
        return redirect("/project/{0}".format(project))
    else:
        error = "Unable to download file {0}".format(module_results)
        return main_page(request, project=project, error=error)


# File View
@login_required
def file_view(request, sha256=False, project='default'):
    if not sha256:
        return render(request, '404.html')
    print sha256
    db = open_db(project)
    # Open a session
    try:
        path = get_sample_path(sha256)
        __sessions__.new(path)
    except:
        return render(request, '404.html')

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
    return render(request, 'file.html', {'file_info': file_info,
                                         'note_list': note_list,
                                         'error_line': False,
                                         'project': project,
                                         'projects': project_list(),
                                         'module_history': module_history
                                         })


# Get module output.
@csrf_exempt
# @login_required
def run_module(request):
    # Get the hash of the file we want to run a command against
    file_hash = request.POST['file_hash']
    if len(file_hash) != 64:
        file_hash = False
    # Lot of logic here to decide what command you entered.
    module_name = request.POST['module']
    module_args = request.POST['args']
    cmd_line = request.POST['cmdline']
    module_history = request.POST['moduleHistory']
    cmd_string = ''
    # Order of precedence
    # moduleHistory, cmd_line, module_name

    if module_history != ' ':
        result = Database().get_analysis(module_history)
        module_results = print_output(json.loads(result.results))
        html = '<p class="text-success">Result for "{0}" stored on {1}</p>'.format(result.cmd_line, result.stored_at)
        html += str(parse_text(module_results))
        return HttpResponse('<pre>{0}</pre>'.format(html))
    if cmd_line:
        cmd_string = cmd_line
    elif module_args:
        cmd_string = '{0} {1}'.format(module_name, mod_dict[module_name][module_args])
    module_results = module_cmdline(cmd_string, file_hash)
    return HttpResponse('<pre>{0}</pre>'.format(str(parse_text(module_results))))


# Hex Viewer
@login_required
def hex_view(request):
    # get post data
    file_hash = request.POST['file_hash']
    try:
        hex_offset = int(request.POST['hex_start'])
    except:
        return '<p class="text-danger">Error Generating Request</p>'
    hex_length = 256

    # get file path
    hex_path = get_sample_path(file_hash)

    # create the command string
    hex_cmd = 'hd -s {0} -n {1} {2}'.format(hex_offset, hex_length, hex_path)

    # get the output
    hex_string = getoutput(hex_cmd)
    # Format the data
    html_string = ''
    hex_rows = hex_string.split('\n')
    for row in hex_rows:
        if len(row) > 9:
            off_str = row[0:8]
            hex_str = row[9:58]
            asc_str = row[58:78]
            asc_str = asc_str.replace('"', '&quot;')
            asc_str = asc_str.replace('<', '&lt;')
            asc_str = asc_str.replace('>', '&gt;')
            html_string += '<div class="row"><span class="text-primary mono">{0}</span> \
                            <span class="text-muted mono">{1}</span> <span class="text-success mono"> \
                            {2}</span></div>'.format(off_str, hex_str, asc_str)
    # return the data
    return HttpResponse(html_string)

@login_required
def yara_rules(request):
    rule_path = os.path.join(VIPER_ROOT, 'data/yara')
    rule_list = os.listdir(rule_path)
    # Read Rules
    if request.method == 'GET':
        action = request.GET.get('action')
        rule = request.GET.get('rule')
        rule_text = ''

        if action == 'list' or action is None:
            return render(request, 'yara.html', {'rule_list': rule_list,
                                                 'rule_text': rule_text
                                                 })
        elif action == 'display' and rule:
            # Display Rule Contents
            rule_file = os.path.join(rule_path, rule)
            if os.path.isfile(rule_file):
                # Only allow .yar or .yara files to be read
                file_name, file_ext = os.path.splitext(rule_file)
                if file_ext in ['.yar', '.yara']:
                    rule_text = open(rule_file, 'r').read()
                else:
                    rule_text = 'Invalid Rule File'
            else:
                rule_text = 'Invalid Rules File'

        elif action == 'delete':
            rule_name = request.GET.get('rulename')
            if rule_name.split('.')[-1] in ['yar', 'yara']:
                os.remove(os.path.join(rule_path, rule_name))
                rule_text = 'Rule {0} Deleted'.format(rule_name)
                # remove from list
                rule_list.remove(rule_name)
            else:
                rule_text = 'Invalid Rule'
            return render(request, 'yara.html', {'rule_list': rule_list,
                                                 'rule_text': rule_text
                                                 })
        else:
            rule_text = 'Invalid Action'

        return render(request, 'yara.html', {'rule_list': rule_list,
                                             'rule_name': rule,
                                             'rule_text': rule_text
                                             })
    # Modify Rules
    elif request.method == 'POST':
        rule_name = request.POST['rule_name']
        rule_text = request.POST['rule_text']
        rule_file = os.path.join(rule_path, rule_name)
        # Prevent storing files in a relative path or with a non yar extension
        rule_test = rule_name.split('.')
        if len(rule_test) == 2 and rule_test[-1] in ['yar', 'yara']:
            # if file exists overwrite
            with open(rule_file, 'w') as rule_edit:
                rule_edit.write(rule_text)
        else:
            rule_text = "The File Name did not match the style 'name.yar'"

        return render(request, 'yara.html', {'rule_list': rule_list,
                                             'rule_name': rule_name,
                                             'rule_text': rule_text
                                             })


# Create Project
@login_required
def create_project(request):
    project_name = request.POST['project'].replace(' ', '_')
    __project__.open(project_name)
    return redirect('/project/{0}'.format(project_name))


# View Config File
@login_required
def config_file(request):
    sections = cfg.__dict__.keys()
    config_values = {}
    for section in sections:
        config_values[section] = cfg.get(section)
    return render(request, 'config.html', {'config_values': config_values})

# Search
@login_required
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
        # get results
        proj_results = []
        rows = db.find(key=key, value=value)
        for row in rows:
            proj_results.append([row.name, row.sha256])
        results.append({'name': project, 'res': proj_results})
    # Return some things
    return render(request, 'search.html', {'results': results})

# Cli Commands
def cli_viewer():
    return render(request, 'cli.html', {'results': results})
