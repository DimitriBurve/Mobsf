# -*- coding: utf_8 -*-
"""Dynamic Analyzer Operations."""
import json
import logging
import os
import random
import re
import subprocess
import threading
import time

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.android.environment import Environment

from MobSF.utils import (get_adb, get_device, is_number, PrintException)

logger = logging.getLogger(__name__)


# Helpers


def json_response(data):
    """Return JSON Response."""
    return HttpResponse(json.dumps(data),
                        content_type='application/json')


def is_attack_pattern(user_input):
    """Check for attacks."""
    atk_pattern = re.compile(r';|\$\(|\|\||&&')
    stat = re.findall(atk_pattern, user_input)
    if stat:
        logger.error('Possible RCE attack detected')
    return stat


def strict_package_check(user_input):
    """Strict package name check."""
    pat = re.compile(r'^\w+\.*[\w\.\$]+$')
    resp = re.match(pat, user_input)
    if not resp:
        logger.error('Invalid package/class name')
    return resp


def is_path_traversal(user_input):
    """Check for path traversal."""
    if (('../' in user_input)
        or ('%2e%2e' in user_input)
        or ('..' in user_input)
            or ('%252e' in user_input)):
        logger.error('Path traversal attack detected')
        return True
    return False


def is_md5(user_input):
    """Check if string is valid MD5."""
    stat = re.match(r'^[0-9a-f]{32}$', user_input)
    if not stat:
        logger.error('Invalid scan hash')
    return stat


def invalid_params():
    """Standard response for invalid params."""
    msg = 'Invalid Parameters'
    logger.error(msg)
    data = {'status': 'failed', 'message': msg}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def mobsfy(request):
    """Configure Instance for Dynamic Analysis."""
    print('MobSFying Android instance')
    data = {}
    try:
        identifier = request.POST['identifier']
        create_env = Environment(identifier)
        if not create_env.connect_n_mount_wo():
            msg = 'Connection failed'
            data = {'status': 'failed', 'message': msg}
            return json_response(data)
        version = create_env.mobsfy_init()
        if not version:
            msg = 'Connection failed'
            data = {'status': 'failed', 'message': msg}
            return json_response(data)
        else:
            data = {'status': 'ok', 'version': version}
    except Exception as exp:
        logger.exception('MobSFying Android instance failed')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def execute_adb(request):
    """Execute ADB Commands."""
    data = {'status': 'ok', 'message': ''}
    cmd = request.POST['cmd']
    port = request.POST['port']
    identifier = get_device(port)
    if cmd:
        args = ["adb",
                '-s',
                identifier,
                'shell']
        try:
            proc = subprocess.Popen(args + cmd.split(' '),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except Exception:
            logger.exception('Executing ADB Commands')
        if stdout or stderr:
            out = stdout or stderr
            out = out.decode('utf8', 'ignore')
        else:
            out = ''
        data = {'status': 'ok', 'message': out}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def get_component(request):
    """Get Android Component."""
    data = {}
    try:
        port = request.POST['port']
        identifier = get_device(port)
        env = Environment(identifier, port)
        comp = request.POST['component']
        bin_hash = request.POST['hash']
        if is_attack_pattern(comp) or not is_md5(bin_hash):
            return invalid_params()
        comp = env.android_component(bin_hash, comp)
        data = {'status': 'ok', 'message': comp}
    except Exception as exp:
        logger.exception('Getting Android Component')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def take_screenshot(request):
    """Take Screenshot."""
    logger.info('Taking screenshot')
    data = {}
    try:
        port = request.POST['port']
        identifier = get_device(port)
        env = Environment(identifier, port)
        bin_hash = request.POST['hash']
        if not is_md5(bin_hash):
            return invalid_params()
        data = {}
        rand_int = random.randint(1, 1000000)
        screen_dir = os.path.join(settings.UPLD_DIR,
                                  bin_hash + '/screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        outile = '{}screenshot-{}.png'.format(
            screen_dir,
            str(rand_int))
        env.screen_shot(outile)
        logger.info('Screenshot captured')
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Taking screenshot')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)
# AJAX


@require_http_methods(['POST'])
def screen_cast(request):
    """ScreenCast."""
    data = {}
    try:
        port = request.POST['port']
        identifier = get_device(port)
        env = Environment(identifier, port)
        trd = threading.Thread(target=env.screen_stream)
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Screen streaming')
        data = {'status': 'failed', 'message': str(exp)}
    print(["[INFO] data screencast : " + str(data)])
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def touch(request):
    """Sending Touch Events."""
    data = {}
    try:
        port = request.POST['port']
        identifier = get_device(port)
        env = Environment(identifier, port)
        x_axis = request.POST['x']
        y_axis = request.POST['y']
        if not is_number(x_axis) and not is_number(y_axis):
            logger.error('Axis parameters must be numbers')
            return invalid_params()
        args = ['input',
                'tap',
                x_axis,
                y_axis]
        trd = threading.Thread(target=env.adb_command,
                               args=(args, True))
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Sending Touch Events')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)


# AJAX


@require_http_methods(['POST'])
def mobsf_ca(request):
    """Install and Remove MobSF Proxy RootCA."""
    data = {}
    try:
        port = request.POST['port']
        identifier = get_device(port)
        env = Environment(identifier, port)
        action = request.POST['action']
        if action == 'install':
            env.install_mobsf_ca(action)
            data = {'status': 'ok', 'message': 'installed'}
        elif action == 'remove':
            env.install_mobsf_ca(action)
            data = {'status': 'ok', 'message': 'removed'}
        else:
            data = {'status': 'failed',
                    'message': 'Action not supported'}
    except Exception as exp:
        logger.exception('MobSF RootCA Handler')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)


def appcrawler_fuzzer(request):
    # adb shell am instrument -e target <package> -w com.eaway.appcrawler.test/android.support.test.runner.AndroidJUnitRunner
    """AppCrawler Fuzzer"""
    print("\n[INFO] Appcrawler Fuzzer")
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        port = request.POST['port']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r";|\$\(|\|\||&&", package):
                print("[ATTACK] Possible RCE")
                return HttpResponseRedirect('/error/')
            if request.method == 'POST':
                base_dir = settings.BASE_DIR
                toolsdir = os.path.join(
                    base_dir, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                data = {}
                adb = "adb"
                identifier = get_device(port)
                subprocess.call(
                    [adb,
                     "-s",
                     identifier,
                     "install",
                     "-r",
                     "/media/dburveni/3806ab9d-f0d1-45c7-9d29-fbfb7f35ed85/mobsf/Audit/_PLATFORM_INSTALLATION_/app"
                     "-crawler/AppCrawlerUtil.apk"]  # modifier PATH
                )
                subprocess.call(
                    [adb,
                     "-s",
                     identifier,
                     "install",
                     "-r",
                     "/media/dburveni/3806ab9d-f0d1-45c7-9d29-fbfb7f35ed85/mobsf/Audit/_PLATFORM_INSTALLATION_/app"
                     "-crawler/AppCrawlerTest.apk"] # modifier PATH
                )
                print(package)
                subprocess.call(
                    [adb,
                     "-s",
                     identifier,
                     "shell",
                     "am",
                     "instrument",
                     "-e",
                     "target",
                     package,
                     "-w",
                     "com.eaway.appcrawler.test/android.support.test.runner.AndroidJUnitRunner"])
                # AVD is much slower, it should get extra time
                # if settings.ANALYZER_IDENTIFIER == "New_Device_API_23_DUP":
                #     wait(8)
                # else:
                wait(5)

                # wait(120)
                # subprocess.call([adb,
                #                 "-s",
                #                 get_identifier(),
                #                 "shell",
                #                 "am",
                #                 "force-stop",
                #                 package])
                # print("\n[INFO] Stopping App")
                data = {'appctest': 'done'}
                return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("[ERROR] Appcrawler Fuzzer")
        return HttpResponseRedirect('/error/')


def wait(sec):
    """Wait in Seconds"""
    print("\n[INFO] Waiting for " + str(sec) + " seconds...")
    time.sleep(sec)


def monkey_fuzzer(request):
    """Monkey Fuzzer"""
    print("\n[INFO] Monkey Fuzzer")
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        port = request.POST['port']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r";|\$\(|\|\||&&", package):
                print("[ATTACK] Possible RCE")
                return HttpResponseRedirect('/error/')
            if request.method == 'POST':
                base_dir = settings.BASE_DIR
                toolsdir = os.path.join(
                    base_dir, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                data = {}
                adb = "adb"
                identifier = get_device(port)
                subprocess.call(
                    [adb,
                      "-s",
                     identifier,
                     "shell",
                     "monkey",
                     "-p",
                     package,
                     "--pct-touch",
                     settings.MONKEY_PCT_TOUCH,
                     "--pct-motion",
                     settings.MONKEY_PCT_MOTION,
                     "--pct-trackball",
                     settings.MONKEY_PCT_TRACKBALL,
                     "--pct-nav",
                     settings.MONKEY_PCT_NAV,
                     "--pct-majornav",
                     settings.MONKEY_PCT_MAJORNAV,
                     "--pct-syskeys",
                     settings.MONKEY_PCT_SYSKEYS,
                     "--pct-appswitch",
                     settings.MONKEY_PCT_APPSWITCH,
                     "--pct-anyevent",
                     settings.MONKEY_PCT_ANYEVENT,
                     "--throttle",
                     settings.MONKEY_THROTTLE,
                     "-v",
                     settings.MONKEY_EVENTS])
                # AVD is much slower, it should get extra time
                # if settings.ANALYZER_IDENTIFIER == "New_Device_API_23_DUP":
                #     wait(8)
                # else:
                wait(6)

                # subprocess.call([adb,
                #                 "-s",
                #                 get_identifier(),
                #                 "shell",
                #                 "am",
                #                 "force-stop",
                #                 package])
                # print "\n[INFO] Stopping App"
                data = {'monktest': 'done'}
                return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("[ERROR] Monkey Fuzzer")
        return HttpResponseRedirect('/error/')
