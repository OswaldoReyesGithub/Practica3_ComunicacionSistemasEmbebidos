from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
import logging
import asyncio
import socket
from aiocoap import *

# un comment the type of test you want to execute
#TEST = "GET"
TEST = "PUT"
#TEST = "DELETE"

URI = "shoe/lace"
PAYLOAD = b"tie"
#PAYLOAD = b"untie"

#URI = "shoe/ledcolor"
#PAYLOAD = b"123456"

#URI = "shoe/steps"

#URI = "shoe/size"

#URI = "shoe/name"
#PAYLOAD = b"Judith"

logging.basicConfig(level=logging.INFO)

async def get(ip, uri):
    protocol = await Context.create_client_context()
    request = Message(code = GET, uri = 'coap://' + ip + '/' +  uri)
    try:
        response = await protocol.request(request).response
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r'%(response.code, response.payload))

async def put(ip, uri, payload):
    context = await Context.create_client_context()
    await asyncio.sleep(2)
    request = Message(code = PUT, payload = payload, uri = 'coap://' + ip +'/' + uri)
    response = await context.request(request).response
    print('Result: %s\n%r'%(response.code, response.payload))

async def delete(ip, uri):
    context = await Context.create_client_context()
    await asyncio.sleep(2)
    request = Message(code = DELETE, uri = 'coap://' + ip +'/' + uri)
    response = await context.request(request).response
    print('Result: %s\n%r'%(response.code, response.payload))

if __name__ == "__main__":
  asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
  zeroconf = Zeroconf()
  info = zeroconf.get_service_info("_coap._udp.local.", "esp32-coap._coap._udp.local.")

  if info:
    print("Device found: {}".format(info))
    ip = socket.inet_ntoa(info.addresses[0])
    print("IP Address: " + ip)
  else:
    print("Device not found!")
    exit(1)

  if(TEST == "GET"):
    print("*** GET ***")
    asyncio.run(get(ip, URI))
  if(TEST == "PUT"):
    print("*** PUT ***")
    asyncio.run(put(ip, URI, PAYLOAD))
    print("*** GET ***")
    asyncio.run(get(ip, URI))
  if(TEST == "DELETE"):
    print("*** DELETE ***")
    asyncio.run(delete(ip, URI))
    print("*** GET ***")
    asyncio.run(get(ip, URI))
  zeroconf.close()