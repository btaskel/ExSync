from server.core import createSocket
from server.client import Client

def run():
    server = createSocket()
    server.createDataSocket()
    server.createCommandSocket()
    server.createVerifySocket()




if __name__ == '__main__':
    run()
