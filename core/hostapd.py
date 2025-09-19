import ctypes
import threading
import time
import settings.paths

HOSTAPD_EXEC_PATH = "hostapd-eaphammer/hostapd/hostapd-eaphammer"
HOSTAPD_LIB_PATH = "hostapd-eaphammer/hostapd/libhostapd-eaphammer.so"


class Hostapd(object):

    def __init__(self, conf_path, debug=False):

        self.exec_path = HOSTAPD_EXEC_PATH
        self.debug = debug
        self.lib_path = HOSTAPD_LIB_PATH

        self.conf_path = conf_path
        self.sleep_time = 4
        self.libhostapd = None
        self.thread = None

    def start(self):

        with open(self.conf_path, "a", encoding="utf-8") as fd:
            fd.write(f"eap_user_file={settings.paths.EAP_USER_FILE}\n")
            fd.write(f"ca_cert={settings.paths.CA_PEM}\n")
            fd.write(f"server_cert={settings.paths.SERVER_PEM}\n")
            fd.write(f"private_key={settings.paths.PRIVATE_KEY}\n")
            fd.write(f"dh_file={settings.paths.DH_FILE}\n")

        argv = [
            self.exec_path,
            "-N",
        ]
        if self.debug:
            argv.append("-d")
        argv.append(self.conf_path)

        # Build argv as bytes for ctypes in Python 3
        argv_bytes = []
        for a in argv:
            if isinstance(a, str):
                argv_bytes.append(a.encode("utf-8"))
            else:
                argv_bytes.append(a)
        argc = len(argv_bytes)
        argv_mem = ctypes.c_char_p * argc
        argv = argv_mem(*argv_bytes)

        self.libhostapd = ctypes.cdll.LoadLibrary(self.lib_path)
        # Ensure main signature is declared for ctypes on some systems
        try:
            self.libhostapd.main.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_char_p),
            ]
            self.libhostapd.main.restype = ctypes.c_int
        except AttributeError:
            pass

        try:

            self.thread = threading.Thread(
                target=self.libhostapd.main, args=(argc, argv)
            )
            self.thread.start()

            print()
            print("[hostapd] AP starting...")
            print()
            time.sleep(self.sleep_time)

        except KeyboardInterrupt:

            self.stop()

    def stop(self):

        print("[hostapd] Terminating event loop...")
        self.libhostapd.eloop_terminate()

        print("[hostapd] Event loop terminated.")

        if self.thread is not None and self.thread.is_alive():

            print("[hostapd] Hostapd worker still running... waiting for it to join.")
            print()
            self.thread.join(5)
            print()
            print("[hostapd] Worker joined.")

        print("[hostapd] AP disabled.")
        print()
