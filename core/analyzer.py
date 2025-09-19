from multiprocessing import Process
from typing import Any

try:
    from scapy.layers.eap import EAP, EAPOL, eap_types
    from scapy.sendrecv import sniff
    from scapy.layers.l2 import Ether
except ImportError:  # pragma: no cover - optional at lint time
    EAP = object  # type: ignore
    EAPOL = object  # type: ignore
    eap_types = {}

    def sniff(**kwargs):  # type: ignore
        raise ImportError("scapy is required to run analyzer")

    class Ether:  # type: ignore
        pass


EAP_MD5_ITEMS = {}


def _to_hex_colon(byte_string: bytes) -> str:
    hexstr = byte_string.hex()
    return ":".join(hexstr[i : i + 2] for i in range(0, len(hexstr), 2))


def analyze_filter(pkt: Any) -> bool:

    if hasattr(pkt, "haslayer") and pkt.haslayer(EAP):

        eap_type = pkt[EAP].type

        if eap_type == 0x1 and pkt[EAP].code == 0x2:

            print("[*] Detected EAP-Identify Response packet...")
            print("[*] Grabbing username...")
            identity = pkt[EAP].identity
            if isinstance(identity, bytes):
                try:
                    identity = identity.decode("utf-8", errors="replace")
                except Exception:
                    identity = repr(identity)
            print(f"[*] Username sniffed: {identity}")

        if eap_type == 0x4:

            eap_id = pkt[EAP].id

            if eap_id not in EAP_MD5_ITEMS:
                EAP_MD5_ITEMS[eap_id] = {}

            if pkt[EAP].code == 0x1:

                challenge = bytes(pkt[EAP].value)
                print("[+] EAP-MD5 Authentication Detected")
                print(" |")
                print(f" ---| MD5 Request ID |--> {eap_id}")
                print(" |")
                print(f" ---| MD5 Challenge  |--> {_to_hex_colon(challenge)}")

                EAP_MD5_ITEMS[eap_id]["challenge"] = challenge.hex()

            if pkt[EAP].code == 0x2:

                response = bytes(pkt[EAP].value)
                print(" |")
                print(f" ---| MD5 Response   |--> {_to_hex_colon(response)}")
                print()
                EAP_MD5_ITEMS[eap_id]["response"] = response.hex()

        elif pkt[EAP].type == 17:
            print("[*] EAP type found: EAP-LEAP")
            print("[*] Suggested attack: rogue gateway")

        elif pkt[EAP].type == 21:
            print("[*] EAP type found: EAP-FAST")
            print("[*] Suggested attack: rogue gateway")

        elif pkt[EAP].type == 32:
            print("[*] EAP type found: EAP-POTP")
            print("[*] Find another device to attack...")

        elif pkt[EAP].type == 47:
            print("[*] EAP type found: EAP-PSK")

        elif pkt[EAP].type == 25:
            print("[*] EAP type found: EAP-PEAP")
            print("[*] Suggested attack: rogue gateway")

        elif pkt[EAP].type == 13:
            print("[*] EAP type found: EAP-TLS... find another device to attack.")

        else:
            try:
                print(f"[*] Skipping packet of type: {eap_types[eap_type]}")
            except Exception:
                print(f"[*] Skipping packet of type: {eap_type}")

    return True


class Analyzer(object):

    def __init__(self, iface: str):

        self.iface = iface
        self.proc = None

    def start(self, timeout: int):

        self.proc = Process(
            target=self._start,
            args=(
                self.iface,
                timeout,
            ),
        )
        self.proc.daemon = True
        self.proc.start()

    def stop(self):

        if self.proc is not None:
            self.proc.terminate()
            self.proc.join()

    @staticmethod
    def _start(iface: str, timeout: int):

        sniff(iface=iface, lfilter=analyze_filter, store=0, timeout=timeout)
