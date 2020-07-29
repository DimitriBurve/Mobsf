# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import subprocess
import time

from shelljob import proc

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render

from DynamicAnalyzer.views.android.environment import Environment
from DynamicAnalyzer.views.android.operations import (
    is_attack_pattern,
    is_md5,
    strict_package_check)
from DynamicAnalyzer.tools.webproxy import (
    start_httptools_ui,
    stop_httptools)

from MobSF.utils import (get_device,
                         get_proxy_ip,
                         print_n_send_error_response)


from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)
tab_avd = [settings.NAME_GENY_0_DUP, settings.NAME_GENY_1_DUP, settings.NAME_GENY_2_DUP, settings.NAME_GENY_3_DUP,
           settings.NAME_GENY_4_DUP]
tab_avd_running = []
tab_avd_not_running = []


def check_name_avd(name):
    cmd = settings.PATH_GENYSHELL + " -c \"devices show\" | grep On | grep '" + name + "$'"
    result_cmd = os.popen(cmd).read()
    # print("[DEBUG] res_cm dev show grep true : " + str(result_cmd))
    return True if result_cmd != "" else False
    # if result_cmd != "":
    #     return True
    # else:
    #     return False


def check_is_avd_running(name):
    return check_name_avd(name)


def add_avd_in_tab(avds):
    for name, is_running in avds.items():
        if not is_running:
            if name not in tab_avd_not_running:
                tab_avd_not_running.append(name)
                if name in tab_avd_running:
                    tab_avd_running.remove(name)

        else:
            if name not in tab_avd_running:
                tab_avd_running.append(name)
            else:
                index_port = tab_avd_running.index(name)
                tab_avd_running.insert(len(tab_avd_running), tab_avd_running.pop(index_port))


def select_avd_name():
    if len(tab_avd_not_running) > 0:
        name = tab_avd_not_running[0]
        if name not in tab_avd_running:
            tab_avd_running.append(tab_avd_not_running.pop(0))
        else:
            index_port = tab_avd_running.index(name)
            tab_avd_running.insert(len(tab_avd_running), tab_avd_running.pop(index_port))
    else:
        name = tab_avd_running[0]

    return name


def avd_free():
    avds = {settings.NAME_GENY_0_DUP: check_is_avd_running(settings.NAME_GENY_0_DUP),
            settings.NAME_GENY_1_DUP: check_is_avd_running(settings.NAME_GENY_1_DUP),
            settings.NAME_GENY_2_DUP: check_is_avd_running(settings.NAME_GENY_2_DUP),
            settings.NAME_GENY_3_DUP: check_is_avd_running(settings.NAME_GENY_3_DUP),
            settings.NAME_GENY_4_DUP: check_is_avd_running(settings.NAME_GENY_4_DUP)}

    print("[DEBUG] list avds (true or false) : " + str(avds))
    add_avd_in_tab(avds)
    print("[INFO] tab avds no running :")
    print(tab_avd_not_running)
    print("[INFO] tab avds running :")
    print(tab_avd_running)
    name = select_avd_name()
    print("[INFO] port selected : " + str(name))
    return name


def end_avd_running(port):
    tab_avd_not_running.append(tab_avd_running.pop(port))


def dynamic_analysis(request):
    """Android Dynamic Analysis Entry point."""
    try:
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk').order_by('-id')
        # try:
        #     # name = avd_free()
        #     identifier = get_device()
        # except Exception:
        #     msg = ('Is Andoird VM running? MobSF cannot'
        #            ' find android instance identifier.'
        #            ' Please run an android instance and refresh'
        #            ' this page. If this error persists,'
        #            ' set ANALYZER_IDENTIFIER in MobSF/settings.py')
        #     return print_n_send_error_response(request, msg)
        # proxy_ip = get_proxy_ip(identifier)
        context = {'apks': apks,
                   # 'identifier': identifier,
                   # 'proxy_ip': proxy_ip,
                   'proxy_port': settings.PROXY_PORT,
                   'title': 'MobSF Dynamic Analysis',
                   'version': settings.MOBSF_VER,
                   'appcrawler': settings.APPCRAWLER_ENABLED,
                   'monkey': settings.MONKEY_ENABLED}
        template = 'dynamic_analysis/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request,
                                           exp)


def dynamic_analyzer(request, api=False):
    """Android Dynamic Analyzer Environment."""
    logger.info('Creating Dynamic Analysis Environment')
    try:
        if api:
            bin_hash = request.POST['hash']
            filename = request.POST['file_name']
            apk = StaticAnalyzerAndroid.objects.get(FILE_NAME=filename)
            field_name = "PACKAGE_NAME"
            package = apk.PACKAGE_NAME
        else:
            bin_hash = request.GET['hash']
            package = request.GET['package']

        no_device = False
        if (is_attack_pattern(package)
                or not is_md5(bin_hash)):
            return print_n_send_error_response(request,
                                               'Invalid Parameters')
        name = avd_free()  # recherche d'un AVD de libre
        # try:
        #     identifier = get_device(name)
        # except Exception:
        #     no_device = True
        # if no_device or not identifier:
        #     msg = ('Is the android instance running? MobSF cannot'
        #            ' find android instance identifier. '
        #            'Please run an android instance and refresh'
        #            ' this page. If this error persists,'
        #            ' set ANALYZER_IDENTIFIER in MobSF/settings.py')
        #     return print_n_send_error_response(request, msg)
        env = Environment(name)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + name
            return print_n_send_error_response(request, msg)
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
        if not env.is_mobsfyied(version):
            msg = ('This Android instance is not MobSfyed.\n'
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance')
            if version < 5:
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you MobSFyed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return print_n_send_error_response(request, msg)
        # Clean up previous analysis
        env.dz_cleanup(bin_hash)
        # Configure Web Proxy
        env.configure_proxy(package)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        # Start Clipboard monitor
        env.start_clipmon()
        # Get Screen Resolution
        screen_width, screen_height = env.get_screen_res()
        logger.info('Installing APK')
        app_dir = os.path.join(settings.UPLD_DIR,
                               bin_hash + '/')  # APP DIRECTORY
        apk_path = app_dir + bin_hash + '.apk'  # APP PATH
        if env.adb_command(['install', '-g', apk_path], False, True) is None:
            env.stop_avd(name)
            return ""
        logger.info('Testing Environment is Ready!')
        context = {'screen_witdth': screen_width,
                   'screen_height': screen_height,
                   'package': package,
                   'md5': bin_hash,
                   'android_version': version,
                   'version': settings.MOBSF_VER,
                   'title': 'Dynamic Analyzer',
                   'appcrawler': settings.APPCRAWLER_ENABLED,
                   'monkey': settings.MONKEY_ENBLED,
                   'name': name,
                   'env': env}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        else:
            return render(request, template, context)
    except Exception:
        logger.exception('Dynamic Analyzer')
        if api:
            return ""
        else:
            return print_n_send_error_response(request,
                                           'Dynamic Analysis Failed.')


def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        stop_httptools(settings.PROXY_PORT)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = ('http://localhost:{}'
               '/dashboard/{}'.format(
                   str(settings.PROXY_PORT),
                   project))
        return HttpResponseRedirect(url)  # lgtm [py/reflective-xss]
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


def logcat(request):
    logger.info('Starting Logcat streaming')
    try:
        pkg = request.GET.get('package')
        if pkg:
            if not strict_package_check(pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name')
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, {'package': pkg})
        app_pkg = request.GET.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name')
            adb = os.environ['MOBSF_ADB']
            g = proc.Group()
            g.run([adb, 'logcat', app_pkg + ':V', '*:*'])

            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
                        time.sleep(.01)
                        yield 'data:{}\n\n'.format(line)
            return StreamingHttpResponse(read_process(),
                                         content_type='text/event-stream')
        return print_n_send_error_response(
            request,
            'Invalid parameters')
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err)
