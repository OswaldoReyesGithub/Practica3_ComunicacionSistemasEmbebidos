import tkinter as tk
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
import socket
import logging
import asyncio
from aiocoap import *
ip = ""
uri = ""
text = ""
info = ""
bandera_service = False

#agregar parametros faltantes