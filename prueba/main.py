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

logging.basicConfig(level=logging.INFO)
def printf(dato):
    global text
    cadena = str(dato)
    text = text + "\n" + cadena
    console_label.config(text=text)
    
async def get(ip, uri):
    global text
    protocol = await Context.create_client_context()
    request = Message(code = GET, uri = 'coap://' + ip + '/' +  uri)
    try:
        response = await protocol.request(request).response
    except Exception as e:
        printf("Failed to fetch resource:" + str(e))

    else:
        printf("Result: "+ str(response.code) + "\n" + str(response.payload))


async def put(ip, uri, payload):
    global text
    context = await Context.create_client_context()
    await asyncio.sleep(2)
    request = Message(code = PUT, payload = payload, uri = 'coap://' + ip +'/' + uri)
    response = await context.request(request).response
    printf("Result"+ str(response.code)+ "\n" + str(response.payload))

async def delete(ip, uri):
    global text
    context = await Context.create_client_context()
    await asyncio.sleep(2)
    request = Message(code = DELETE, uri = 'coap://' + ip +'/' + uri)
    response = await context.request(request).response
    printf("Result"+ str(response.code)+ "\n" + str(response.payload))

def get_data():
    if(bandera_service == True):
        global text,ip,uri
        selected_item = listbox.get(listbox.curselection())
        uri = str(selected_item)
        printf("Uri seleccionado: " + str(selected_item) + "\nPETICION : GET")
        asyncio.run(get(ip, uri))
    else:
        printf("No se ha conectado con el servicio antes")

def delete_data():
    if(bandera_service == True):
        global text,ip,uri
        selected_item = listbox.get(listbox.curselection())
        uri = str(selected_item)
        printf("Uri seleccionado: " + str(selected_item) + "\nPETICION : DELETE")
        asyncio.run(delete(ip, uri))
    else:
        printf("No se ha conectado con el servicio antes")

def put_data():
    if(bandera_service == True):
        global text
        selected_item = listbox.get(listbox.curselection())
        uri = str(selected_item)
        payload_str = (entry3.get())
        payload = payload_str.encode()
        printf("Uri seleccionado: " + str(selected_item) + "\nPETICION : PUT")
        printf(("Cadena enviada: ") + payload_str)
        asyncio.run(put(ip, uri, payload))
    else:
        printf("No se ha conectado con el servicio antes")


def reset_fields():
    global text
    entry3.delete(0, tk.END)
    text = ""
    console_label.config(text=text)  # Limpiar la "consola"

def clear_terminal():
    global text
    text = ""
    console_label.config(text=text)

def start():
    if(bandera_service == 1):
        printf("Conexion establecida")
    else:
        printf("Conexion rechazada")
    

# Crear la ventana principal
root = tk.Tk()
root.title("Interfaz de Usuario")

button1 = tk.Button(root, text="START",command=start)
button1.pack()

# Listbox para seleccionar elementos
listbox = tk.Listbox(root, height=5, width=40)
listbox.pack(pady=10)

# Agregar elementos al Listbox
for item in ["shoe/lace", "shoe/name", "shoe/ledcolor", "shoe/size", "shoe/steps"]:
    listbox.insert(tk.END, item)

# Botones GET y DELETE
button_frame1 = tk.Frame(root)
button_frame1.pack(pady=5)

get_button = tk.Button(button_frame1, text="GET", command=get_data)
get_button.pack(side=tk.LEFT, padx=5)

delete_button = tk.Button(button_frame1, text="DELETE", command=delete_data)
delete_button.pack(side=tk.LEFT, padx=5)

# Entrada de texto 3
entry3 = tk.Entry(root, width=40)
entry3.pack(pady=10)

# Botón PUT
put_button = tk.Button(root, text="PUT", command=put_data)
put_button.pack(pady=5)

# Label que simula la consola
console_label = tk.Label(root, text="", bg="black", fg="green", width=40, height=10,anchor="sw",justify="left",font="arial")
console_label.pack(pady=10)

# Button frame 2
button_frame2 = tk.Frame(root)
button_frame2.pack(pady=5)

# Botón RESET
reset_button = tk.Button(button_frame2, text="RESET", command=reset_fields)
reset_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Botón CLEAR
clear_button = tk.Button(button_frame2, text="CLEAR", command=clear_terminal)
clear_button.pack(side=tk.LEFT, padx=10, pady=10)

if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    zeroconf = Zeroconf()
    info = zeroconf.get_service_info("_coap._udp.local.", "esp32-coap._coap._udp.local.")
    printf("Starting connection with the ESP32 service...")
    if info:
        print("Device found: {}".format(info))
        ip = socket.inet_ntoa(info.addresses[0])
        bandera_service = True
        printf("IP Address: " + str(ip))
    else:
        printf("Device not found!")
        bandera_service = False
    # Ejecutar la aplicación
root.mainloop()