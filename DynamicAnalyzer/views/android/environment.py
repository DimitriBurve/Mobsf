# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import io
import logging
import os
import re
import shutil
import subprocess
import time
import threading
import platform

from OpenSSL import crypto

from django.conf import settings

from DynamicAnalyzer.tools.webproxy import (get_ca_dir,
                                            start_proxy,
                                            stop_httptools)

from StaticAnalyzer.models import StaticAnalyzerAndroid

from MobSF.utils import (get_adb,
                         get_device,
                         get_proxy_ip,
                         python_list, PrintException, getADB)

logger = logging.getLogger(__name__)


class Environment:

    def __init__(self, identifier=None, name=None):
        if name:
            self.name = name
        else:
            self.name = "Google Pixel 3_DUP"

        self.identifier = identifier

        self.tools_dir = settings.TOOLS_DIR

    def wait(self, sec):
        """Wait in Seconds."""
        logger.info('Waiting for %s seconds...', str(sec))
        time.sleep(sec)

    def check_connect_error(self, output):
        """Check if connect failed."""
        if b'unable to connect' in output or b'failed to connect' in output:
            logger.error('%s', output.decode('utf-8').replace('\n', ''))
            return False
        return True

    def run_subprocess_verify_output(self, command):
        """Run subprocess and verify execution."""
        out = subprocess.check_output(command)
        self.wait(2)
        return self.check_connect_error(out)

    def avd_reference_name(self):
        if self.name == settings.NAME_GENY_0_DUP:
            return [settings.NAME_GENY_0, settings.NAME_GENY_0_DUP]
        elif self.name == settings.NAME_GENY_1_DUP:
            return [settings.NAME_GENY_1, settings.NAME_GENY_1_DUP]
        elif self.name == settings.NAME_GENY_2_DUP:
            return [settings.NAME_GENY_2, settings.NAME_GENY_2_DUP]
        elif self.name == settings.NAME_GENY_3_DUP:
            return [settings.NAME_GENY_3, settings.NAME_GENY_3_DUP]
        elif self.name == settings.NAME_GENY_4_DUP:
            return [settings.NAME_GENY_4, settings.NAME_GENY_4_DUP]

    def connect_n_mount(self):
        """Test ADB Connection."""
        # self.adb_command(['kill-server'])
        # self.adb_command(['start-server'])
        logger.info('ADB Restarted')
        self.wait(2)
        logger.info('Connecting to Android %s', self.name)
        toolsdir = os.path.join(
            settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
        adb = "adb"
        names = self.avd_reference_name()
        self.refresh_avd(adb, settings.AVD_PATH, names[0], names[1],
                         settings.AVD_EMULATOR, self.name)
        # if not self.run_subprocess_verify_output([get_adb(),
        #                                          'connect',
        #                                           self.identifier]):
        #     return False
        # logger.info('Restarting ADB Daemon as root')
        # if not self.run_subprocess_verify_output([get_adb(), 'root']):
        #     return False
        # logger.info('Reconnect to Android Device')
        # # connect again with root adb
        # if not self.run_subprocess_verify_output(["adb",
        #                                          'connect',
        #                                           self.identifier]):
        #     return False
        # mount system
        # logger.info('Remounting /system')

        # self.adb_command(['mount', '-o',
        #                   'rw,remount', '/system'], True)
        return True

    def adb_command(self, cmd_list, shell=False, silent=False):
        """ADB Command wrapper."""
        args = ["adb",
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list

        print("[DEBUG] args adb command : " + str(args))

        try:
            result = subprocess.check_output(args)
            return result
        except Exception as e:
            if not silent:
                print(e)
                logger.exception('Error Running ADB Command')
            return None

    def dz_cleanup(self, bin_hash):
        """Clean up before Dynamic Analysis."""
        # Delete ScreenStream Cache
        screen_file = os.path.join(settings.SCREEN_DIR, 'screen.png')
        if os.path.exists(screen_file):
            os.remove(screen_file)
        # Delete Contents of Screenshot Dir
        screen_dir = os.path.join(
            settings.UPLD_DIR, bin_hash + '/screenshots-apk/')
        if os.path.isdir(screen_dir):
            shutil.rmtree(screen_dir)
        else:
            os.makedirs(screen_dir)

    def configure_proxy(self, project):
        """HTTPS Proxy."""
        proxy_port = settings.PROXY_PORT
        logger.info('Starting HTTPs Proxy on %s', proxy_port)
        stop_httptools(proxy_port)
        start_proxy(proxy_port, project)

    def install_mobsf_ca(self, action):
        """Install or Remove MobSF Root CA."""
        ca_construct = '{}.0'
        pem = open(get_ca_dir(), 'rb').read()
        ca_file = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
        ca_file_hash = hex(ca_file.subject_name_hash()).lstrip('0x')
        ca_file = os.path.join('/system/etc/security/cacerts/',
                               ca_construct.format(ca_file_hash))
        if action == 'install':
            logger.info('Installing MobSF RootCA')
            self.adb_command(['push',
                              get_ca_dir(),
                              ca_file])
            self.adb_command(['chmod',
                              '644',
                              ca_file], True)
        elif action == 'remove':
            logger.info('Removing MobSF RootCA')
            self.adb_command(['rm',
                              ca_file], True)
        # with a high timeout afterwards

    def set_global_proxy(self, version):
        """Set Global Proxy on device."""
        # Android 4.4+ supported
        proxy_ip = None
        proxy_port = settings.PROXY_PORT
        if version < 5:
            proxy_ip = get_proxy_ip(self.identifier)
        else:
            proxy_ip = settings.PROXY_IP
        if proxy_ip:
            if version < 4.4:
                logger.warning('Please set Android VM proxy as %s:%s',
                               proxy_ip, proxy_port)
                return
            logger.info('Setting Global Proxy for Android VM')
            self.adb_command(
                ['settings',
                 'put',
                 'global',
                 'http_proxy',
                 '{}:{}'.format(proxy_ip, proxy_port)], True)

    def unset_global_proxy(self):
        """Unset Global Proxy on device."""
        logger.info('Removing Global Proxy for Android VM')
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'http_proxy'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_host'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_port'], True)

    def enable_adb_reverse_tcp(self, version):
        """Enable ADB Reverse TCP for Proxy."""
        # Androd 5+ supported
        if not version >= 5:
            return
        proxy_port = settings.PROXY_PORT
        logger.info('Enabling ADB Reverse TCP on %s', proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        try:
            proc = subprocess.Popen(["adb",
                                     '-s', self.identifier,
                                     'reverse', tcp, tcp],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'error: closed' in stderr:
                logger.warning('ADB Reverse TCP works only on'
                               ' Android 5.0 and above. Please '
                               'configure a reachable IP Address'
                               ' in Android proxy settings.')
            elif stderr:
                logger.error(stderr.decode('utf-8').replace('\n', ''))
        except Exception:
            logger.exception('Enabling ADB Reverse TCP')

    def start_clipmon(self):
        """Start Clipboard Monitoring."""
        logger.info('Starting Clipboard Monitor')
        args = ['am', 'startservice',
                'opensecurity.clipdump/.ClipDumper']
        self.adb_command(args, True)

    def get_screen_res(self):
        """Get Screen Resolution of Android Instance."""
        logger.info('Getting screen resolution')
        try:
            resp = self.adb_command(['dumpsys', 'window'], True)
            scn_rgx = re.compile(r'mUnrestrictedScreen=\(0,0\) .*')
            scn_rgx2 = re.compile(r'mUnrestricted=\[0,0\]\[.*\]')
            match = scn_rgx.search(resp.decode('utf-8'))
            if match:
                screen_res = match.group().split(' ')[1]
                width, height = screen_res.split('x', 1)
                return width, height
            match = scn_rgx2.search(resp.decode('utf-8'))
            if match:
                res = match.group().split('][')[1].replace(']', '')
                width, height = res.split(',', 1)
                return width, height
            else:
                logger.error('Error getting screen resolution')
        except Exception:
            logger.exception('Getting screen resolution')
        return '1440', '2560'

    def screen_shot(self, outfile):
        """Take Screenshot."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/screen.png'], True)
        self.adb_command(['pull',
                          '/data/local/screen.png',
                          outfile])

    def screen_stream(self):
        """Screen Stream."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/stream.png'],
                         True)
        self.adb_command(['pull',
                          '/data/local/stream.png',
                          '{}screen{}.png'.format(settings.SCREEN_DIR, self.name)])

    def android_component(self, bin_hash, comp):
        """Get APK Components."""
        anddb = StaticAnalyzerAndroid.objects.filter(MD5=bin_hash)
        resp = []
        if comp == 'activities':
            resp = python_list(anddb[0].ACTIVITIES)
        elif comp == 'receivers':
            resp = python_list(anddb[0].RECEIVERS)
        elif comp == 'providers':
            resp = python_list(anddb[0].PROVIDERS)
        elif comp == 'services':
            resp = python_list(anddb[0].SERVICES)
        elif comp == 'libraries':
            resp = python_list(anddb[0].LIBRARIES)
        elif comp == 'exported_activities':
            resp = python_list(anddb[0].EXPORTED_ACTIVITIES)
        return '\n'.join(resp)

    def get_android_version(self):
        """Get Android version."""
        out = self.adb_command(['getprop',
                                'ro.build.version.release'], True)
        and_version = out.decode('utf-8').rstrip()
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        return float(and_version)

    def get_android_arch(self):
        """Get Android Architecture."""
        out = self.adb_command(['getprop',
                                'ro.product.cpu.abi'], True)
        return out.decode('utf-8').rstrip()

    def launch_n_capture(self, package, activity, outfile):
        """Launch and Capture Activity."""
        self.adb_command(['am',
                          'start',
                          '-n',
                          package + '/' + activity], True)
        self.wait(3)
        self.screen_shot(outfile)
        logger.info('Activity screenshot captured')
        logger.info('Stopping app')
        self.adb_command(['am', 'force-stop', package], True)

    def is_mobsfyied(self, android_version):
        """Check is Device is MobSFyed."""
        print('Environment MobSFyed Check')
        if android_version < 5:
            agent_file = '.mobsf-x'
            agent_str = b'MobSF-Xposed'
        else:
            agent_file = '.mobsf-f'
            agent_str = b'MobSF-Frida'
        try:
            out = subprocess.check_output(
                ["adb",
                 '-s', self.identifier,
                 'shell',
                 'cat',
                 '/system/' + agent_file])
            if agent_str not in out:
                return False
        except Exception:
            return False
        return True

    def mobsfy_init(self):
        """Init MobSFy."""
        version = self.get_android_version()
        print('2Android Version identified as %s', version)
        try:
            if version < 5:
                self.xposed_setup(version)
                self.mobsf_agents_setup('xposed')
            else:
                self.frida_setup()
                self.mobsf_agents_setup('frida')
            print('MobSFying Completed!')
            return version
        except Exception:
            print('[ERROR] Failed to MobSFy Android Instance')
            return False

    def mobsf_agents_setup(self, agent):
        """Setup MobSF agents."""
        # Install MITM RootCA
        self.install_mobsf_ca('install')
        # Install MobSF Agents
        mobsf_agents = 'onDevice/mobsf_agents/'
        clip_dump = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 'ClipDump.apk')
        logger.info('Installing MobSF Clipboard Dumper')
        self.adb_command(['install', '-r', clip_dump])
        if agent == 'frida':
            agent_file = '.mobsf-f'
        else:
            agent_file = '.mobsf-x'
        mobsf_env = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 agent_file)
        self.adb_command(['push', mobsf_env, '/system/' + agent_file])

    def xposed_setup(self, android_version):
        """Setup Xposed."""
        xposed_dir = 'onDevice/xposed/'
        xposed_modules = xposed_dir + 'modules/'
        if android_version < 5:
            logger.info('Installing Xposed for Kitkat and below')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'Xposed.apk')
            hooks = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'hooks.json')
            droidmon = os.path.join(self.tools_dir,
                                    xposed_modules,
                                    'Droidmon.apk')
            logger.info('Installing Droidmon API Analyzer')
            self.adb_command(['install', '-r', droidmon])
            logger.info('Copying Droidmon hooks config')
            self.adb_command(['push', hooks, '/data/local/tmp/'])
        else:
            logger.info('Installing Xposed for Lollipop and above')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'XposedInstaller_3.1.5.apk')
        self.adb_command(['install', '-r', xposed_apk])
        # Xposed Modules and Support Files
        justrustme = os.path.join(self.tools_dir,
                                  xposed_modules,
                                  'JustTrustMe.apk')
        rootcloak = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'RootCloak.apk')
        proxyon = os.path.join(self.tools_dir,
                               xposed_modules,
                               'mobi.acpm.proxyon_v1_419b04.apk')
        sslunpin = os.path.join(self.tools_dir,
                                xposed_modules,
                                'mobi.acpm.sslunpinning_v2_37f44f.apk')
        bluepill = os.path.join(self.tools_dir,
                                xposed_modules,
                                'AndroidBluePill.apk')
        logger.info('Installing JustTrustMe')
        self.adb_command(['install', '-r', justrustme])
        logger.info('Installing SSLUnpinning')
        self.adb_command(['install', '-r', sslunpin])
        logger.info('Installing ProxyOn')
        self.adb_command(['install', '-r', proxyon])
        logger.info('Installing RootCloak')
        self.adb_command(['install', '-r', rootcloak])
        logger.info('Installing Android BluePill')
        self.adb_command(['install', '-r', bluepill])
        logger.info('Launching Xposed Framework.')
        xposed_installer = ('de.robv.android.xposed.installer/'
                            'de.robv.android.xposed.installer.'
                            'WelcomeActivity')
        self.adb_command(['am', 'start', '-n',
                          xposed_installer], True)

    def frida_setup(self):
        """Setup Frida."""
        frida_dir = 'onDevice/frida/'
        frida_bin = os.path.join(self.tools_dir,
                                 frida_dir,
                                 'frida-server-12.8.14-android-x86')
        arch = self.get_android_arch()
        print('Android instance architecture identified as %s', arch)
        if 'x86' not in arch:
            logger.error('Make sure a Genymotion Android x86'
                         'instance is running')
            return
        print('Copying frida server')
        self.adb_command(['push', frida_bin, '/system/fd_server'])
        self.adb_command(['chmod', '755', '/system/fd_server'], True)

    def run_frida_server(self, name):
        self.identifier = get_device(name)
        """Start Frida Server."""
        check = self.adb_command(['ps'], True)
        print(str(check))
        if b'fd_server' in check:
            logger.info('Frida Server is already running')
            return

        # def start_frida():
        #     fnull = open(os.devnull, 'w')
        #     argz = [get_adb(),
        #             '-s',
        #             self.identifier,
        #             'shell',
        #             '/system/fd_server &']
        #     subprocess.call(argz, stdout=fnull, stderr=subprocess.STDOUT)
        #
        # trd = threading.Thread(target=start_frida())
        # trd.daemon = True
        # trd.start()
        os.system("adb shell /system/fd_server &")
        os.system("adb shell ps | grep fd")
        print('\n[INFO] Starting Frida Server')
        print('Waiting for 2 seconds...')
        time.sleep(2)

    def start_avd(self, emulator, avd_name, emulator_port):
        """Start AVD"""
        print("\n[INFO] Starting MobSF Emulator")
        try:
            # args = [
            #     emulator,
            #     '-avd',
            #     avd_name,
            #     "-no-boot-anim",
            #     "-writable-system",
            #     # "-no-window",
            #     "-no-snapshot-save",
            #     # "-netspeed",
            #     # "full",
            #     # "-netdelay",
            #     # "none",
            #     "-port",
            #     str(emulator_port),
            # ]

            args = [
                settings.PATH_GMTOOL,
                "admin",
                "start",
                avd_name
                # "Google Pixel 3"
            ]

            print("TOTO")

            if platform.system() == 'Darwin':
                # There is a strage error in mac with the dyld one in a while..
                # this should fix it..
                if 'DYLD_FALLBACK_LIBRARY_PATH' in os.environ.keys():
                    del os.environ['DYLD_FALLBACK_LIBRARY_PATH']

            subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            print("TOTO2")

            time.sleep(10)
            self.identifier = get_device(avd_name)
            print(str(self.identifier))
            if not self.identifier:
                time.sleep(10)
                self.identifier = get_device(self.name)
            time.sleep(5)
            args = ["adb",
                    "-s",
                    self.identifier,
                    "wait-for-device"]
            # subprocess.call(args)
            # os.system("adb devices")
            # os.system("adb -s " + self.identifier + " wait-for-device")
            # print("TOTO3")
            # os.system("adb devices")
            # print("TOTO4")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "root"]
            # )
            # print("TOTO5")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "remount"]
            # )
            # print("TOTO6")
            # path_origin = "/media/dburveni/3806ab9d-f0d1-45c7-9d29-fbfb7f35ed85/mobsf/Audit/_PLATFORM_INSTALLATION_/MobSF/supersu/x86/su.pie"
            # path_destination1 = "/system/bin/su"
            # path_destination2 = "/system/xbin/su"
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "push",
            #      path_origin,
            #      path_destination1]
            # )
            # print("TOTO7")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "push",
            #      path_origin,
            #      path_destination2]
            # )
            # print("TOTO8")
            # time.sleep(2)
            # print("[INFO] Debut lancement root")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "chmod 06755 /system/bin/su"]
            # )
            # print("TOTO9")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "chmod 06755 /system/xbin/su"]
            # )
            # print("TOTO10")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "setenforce 0"]
            # )
            # print("TOTO11")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "/system/bin/su --install"]
            # )
            # print("TOTO12")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "/system/bin/su --daemon&"]
            # )
            # print("TOTO13")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "/system/xbin/su --install"]
            # )
            # print("TOTO14")
            # subprocess.call(
            #     ["adb",
            #      "-s",
            #      self.identifier,
            #      "shell",
            #      "/system/xbin/su --daemon&"]
            # )
            # print("TOTO15")
            # os.system("adb -s " + self.identifier + " shell am start eu.chainfire.supersu/.MainActivity")
            # print("TOTO16")
            # os.system("adb -s " + self.identifier + " shell input keyevent KEYCODE_HOME")
            # os.system("adb shell /system/fd_server &")

        except:
            PrintException("[ERROR] Starting MobSF Emulator")

    def stop_avd(self, name):
        """Stop AVD"""
        print("\n[INFO] Stopping MobSF Emulator")
        try:
            # adb -s emulator-xxxx emu kill
            FNULL = open(os.devnull, 'w')
            # args = [adb, '-s', self.identifier, 'emu', 'kill']
            args = [settings.PATH_GMTOOL,
                    "admin",
                    "stop",
                    name
                    # "Google Pixel 3"
                    ]
            subprocess.call(args, stderr=FNULL)
            # os.system("adb emu kill")
        except:
            PrintException("[ERROR] Stopping MobSF Emulator")

    def delete_avd(self, avd_name):
        """Delete AVD"""
        print("\n[INFO] Deleting emulator files")
        try:
            # config_file = os.path.join(avd_path, avd_name + '.ini')
            # if os.path.exists(config_file):
            #     os.remove(config_file)
            # '''
            # # todo: Sometimes there is an error here because of the locks that avd
            # # does - check this out
            # '''
            # avd_folder = os.path.join(avd_path, avd_name + '.avd')
            # if os.path.isdir(avd_folder):
            #     shutil.rmtree(avd_folder)
            FNULL = open(os.devnull, 'w')
            # args = [adb, '-s', self.identifier, 'emu', 'kill']
            args = [settings.PATH_GMTOOL,
                    "admin",
                    "delete",
                    avd_name,
                    ]
            subprocess.call(args, stderr=FNULL)
        except:
            PrintException("[ERROR] Deleting emulator files")

    def duplicate_avd(self, reference_name, dup_name):
        """Duplicate AVD"""
        print("\n[INFO] Duplicating MobSF Emulator")
        try:
            # reference_ini = os.path.join(avd_path, reference_name + '.ini')
            # dup_ini = os.path.join(avd_path, dup_name + '.ini')
            # reference_avd = os.path.join(avd_path, reference_name + '.avd')
            # dup_avd = os.path.join(avd_path, dup_name + '.avd')
            #
            # # Copy the files from the referenve avd to the one-time analysis avd
            # shutil.copyfile(reference_ini, dup_ini)
            # shutil.copytree(reference_avd, dup_avd)
            #
            # # Replacing every occuration of the reference avd name to the dup one
            # for path_to_update in [dup_ini,
            #                        os.path.join(dup_avd, 'hardware-qemu.ini'),
            #                        os.path.join(dup_avd, 'config.ini')
            #                        ]:
            #     with io.open(path_to_update, mode='r', encoding="utf8", errors="ignore") as fled:
            #         replaced_file = fled.read()
            #         replaced_file = replaced_file.replace(reference_name, dup_name)
            #     with io.open(path_to_update, 'w') as fled:
            #         fled.write(replaced_file)
            FNULL = open(os.devnull, 'w')
            # args = [adb, '-s', self.identifier, 'emu', 'kill']
            args = [settings.PATH_GMTOOL,
                    "admin",
                    "clone",
                    reference_name,
                    dup_name,
                    "sdk_path=/usr/lib/android-sdk/"
                    ]
            subprocess.call(args, stderr=FNULL)
        except:
            PrintException("[ERROR] Duplicating MobSF Emulator")

    def refresh_avd(self, adb, avd_path, reference_name, dup_name, emulator, port):
        """Refresh AVD"""
        print("\n[INFO] Refreshing MobSF Emulator")
        try:
            # Stop existing emulator on the spesified port
            self.stop_avd(dup_name)

            # Windows has annoying lock system, it takes time for it to remove the locks after we stopped the emulator
            if platform.system() == 'Windows':
                time.sleep(3)

            # Delete old emulator
            self.delete_avd(dup_name)

            # Copy and replace the contents of the reference machine
            self.duplicate_avd(reference_name, dup_name)

            # Start emulator
            self.start_avd(emulator, dup_name, port)
        except:
            PrintException("[ERROR] Refreshing MobSF VM")
