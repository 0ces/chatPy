'''
Modulo chatPyServer.py

Proyecto final de automatas y lenguajes formales

Realizado por:
    Laura Jaimes
    Diego Landinez
    Edwar Plata

Implementado por:
    Edwar Plata
'''

from socket import socket, AF_INET, SOCK_STREAM, error
from threading import Thread, currentThread
from time import sleep, localtime, gmtime
from sys import exit
from hashlib import sha256, md5
from json import loads, load, dump
from random import randint
from automata.tm.dtm import DTM

class Server():
    '''
    Clase encargada del manejo del servidor.
    '''
    def __init__(self, ip, port):
        '''
        Constructor de la clase.

        Parametros:
            - ip: str
            - port: int

        El constructor se encarga de inicializar todos los attributos utilizados
        por la clase.

        Intentará crear crear un servidor socket en la ip y puerto especificado
        de no ser posible generará un mensaje de error y se cerrará.

        Tambien inicializará un thread encargado de ejecutar el metodo listen en
        modo daemon.
        '''
        self.ip, self.port, self.server = ip, port, socket(AF_INET, SOCK_STREAM)
        self.WARNING = self.getInfoType('WARN',33)
        self.INFO = self.getInfoType('INFO',34)
        self.STATUS = self.getInfoType('STAT',32)
        self.ERROR = self.getInfoType('FAIL',31)
        self.datos = load(open('datos.json','r'))
        self.mt1 = self.Mt1()
        self.mt2 = self.Mt2()
        try:
            self.server.bind((self.ip,self.port))
        except OSError:
            print('{} {} No se ha podido iniciar el servidor.'.format(self.ERROR,self.getTime()))
            print('{} {} Cerrando servidor.'.format(self.STATUS,self.getTime()))
            exit()
        print('{} {} Servidor creado correctamente'.format(self.STATUS,self.getTime()))
        self.threads = [
            Thread(target=self.listen, daemon=True),
            # Thread(target=self.checkDatos, daemon=True)
        ]
        self.conexiones = []
        for thread in self.threads:
            thread.start()

    def listen(self):
        '''
        Metodo encargado de escuchar las conexiones entrantes.

        En su bucle principal se esperará por cada conexion entrante,
        en caso de recibir alguna procederá a crear un objeto Conexion
        de la conexion entrante, luego creará un thread encargado
        de recibir la informacion entrante de esa conexion.
        '''
        print('{} {} Escuchando en {}:{}'.format(self.STATUS,self.getTime(),self.ip,self.port))
        while True:
            self.server.listen()
            conn, addr = self.server.accept()
            print('{} {} Se ha recibido una conexion de {}:{}'.format(self.STATUS,self.getTime(),addr[0],addr[1]))
            conexion = Conexion(conn,addr)
            connThread = Thread(target=self.getDataFromConn, args=(conexion,))
            connThread.start()
            conexion.setThread(connThread)
            self.threads.append(connThread)
            self.conexiones.append(conexion)

    def disconnectConn(self, index):
        '''
        Metodo encargado de desconectar una conexion dado su indice en la
        lista self.conexiones
        '''
        self.conexiones[index].disconnected()
        print('{} {} {} se desconecto.'.format(self.STATUS,self.getTime(),self.conexiones[index].getAddr()[0]))
        self.threads.remove(self.conexiones[index].getThread())
        self.conexiones.pop(index)

    def authenticate(self, conexion, user, password):
        '''
        Metodo encargado de la autenticación de un cliente

        Parametros:
            conexion: Conexion
            user: str
            password: str

        El metodo creará un diccionario en el cual se especificará
        que se trata de un paquete de autenticacion, luego verificará
        que los datos recibidos del usuario coincidan con los datos
        almacenados, si es asi se generará un numero aleatorio
        de 16 digitos y se generará un token el cual se enviará al cliente
        para que pueda generar el token. En caso de que los datos de
        autenticación no sean correctos se enviará un paquete vacio en el
        cual se da entender al cliente que la autenticacion no fue correcta,
        en caso de no poder enviar dicho paquete el servidor procederá a
        eliminar la conexion.

        Posteriormente se procederá a revisar si el token recibido por
        el cliente concide con el generado por parte del servidor de ser
        así se le enviará un paquete de confirmacion al cliente, de lo
        contrario se enviará un paquete sin contenido avisando del fallo
        a la hora de generar el token.
        '''
        data = {}
        data['type'] = 'auth'
        data['payload'] = {}
        if user in self.datos and self.datos[user]['password'] == password:
            conexion.setIsAuth()
            conexion.setColor(self.datos[user]['color'])
            print('{} {} {} se ha autenticado correctamente.'.format(self.INFO, self.getTime(), user))
            data['payload']['authenticated'] = 'True'
            randomInt = randint(1000000000000000,9999999999999999)
            conexion.setToken(self.generateToken(randomInt, conexion))
            data['payload']['secret'] = f'{randomInt}'
            conexion.send(f'{data}')
            rawDataFromConn = conexion.recv().replace('\'','"')
            dataFromConn = loads(rawDataFromConn)
            data = {}
            data['type'] = 'checkToken'
            data['payload'] = {}
            if dataFromConn['type'] == 'checkToken':
                if dataFromConn['payload']['token'] == self.doMd5(conexion.getToken()):
                    data['payload']['correctToken'] = 'True'
                    conexion.send(f'{data}')
                    data = {
                        'type': 'getColores',
                        'payload': self.getColores()
                    }
                    conexion.send(f'{data}')
                    return True
                else:
                    data['payload']['correctToken'] = ''
                    conexion.send(f'{data}')
                    return False
        else:
            print('{} {} {} no se ha autenticado correctamente.'.format(self.INFO, self.getTime(), conexion.getAddr()[0]))
            data['payload']['authenticated'] = ''
            data['payload']['secret'] = 0
            try:
                conexion.send(f'{data}')
            except:
                self.disconnectConn(self.conexiones.index(conexion))
            return False

    def getDataFromConn(self, conexion):
        '''
        Metodo encargado de recibir la información de la conexion dada

        Parametros:
            - conexion: Conexion

        Primero se recibirá las credenciales de autenticacion de la conexion
        luego se hará un intento de autenticacion si éste falla se volverá
        a pedir las credenciales, en caso de que a los 3 intentos la
        autenticacion falle se desconectará la conexion.

        Si la conexión sigue estando activa es decir, se ha podido autenticar
        se procederá a recibir todos los paquetes enviados desde el cliente
        y se revisará si el paquete contiene información de no ser así
        se interpretará como que se ha cerrado la conexión. En caso de que haya
        informacion en el paquete se procederá a verificar el tipo del paquete
        el cual puede ser:
            - msg:
                Es decir el paquete recibido corresponde a un mensaje
                enviado desde el cliente.
            - changeSettings:
                Es decir el cliente ha cambiado su color y por lo tanto
                hay que hacer el respectivo cambio en el archivo datos.json
        En cualquiera de los tipos de mensaje se verificará si el token es el
        cual está activo para dicha conexion de no ser así el paquete será
        ignorado.
        '''
        user, password = conexion.login()
        attempt = 0
        while not self.authenticate(conexion,user,password):
            if attempt < 3:
                user, password = conexion.login()
                attempt += 1
            else:
                self.disconnectConn(self.conexiones.index(conexion))
                break
        while conexion.isConnected():
            rawDataFromConn = conexion.recv()
            if rawDataFromConn:
                dataFromConn = loads(rawDataFromConn)
                if dataFromConn['type'] == 'msg' and dataFromConn['payload']['token'] == self.doMd5(conexion.getToken()):
                    print('{} {} {} envio: {}'.format(self.STATUS,dataFromConn['payload']['time'],user,dataFromConn['payload']['msg']))
                    dataFromConn['payload']['token'] = conexion.getToken()
                    self.sendDataToConns(dataFromConn)
                elif dataFromConn['type'] == 'changeSettings' and dataFromConn['payload']['token'] == self.doMd5(conexion.getToken()):
                    print(f'{self.STATUS} {self.getTime()} {user} cambio sus ajustes.')
                    self.setColores(dataFromConn["payload"]["user"], dataFromConn["payload"]["color"])
                    dataFromConn['payload']['token'] = conexion.getToken()
                    self.sendDataToConns(dataFromConn)
            else:
                self.disconnectConn(self.conexiones.index(conexion))

    def generateToken(self, randomInt, conexion):
        '''
        Metodo encargado de generar el token de autenticacion

        Parametros:
            - randomInt: int
            - conexion: Conexion

        La idea es que cada conexion va a tener un token unico el cual será
        verificado cada vez que se reciba un paquete de esa conexion.

        El token es generado mediante la concatenación de:
            - El nombre de usuario
            - La clave del usuario
            - El numero aleatorio recibido en los parametros del metodo
            - El año actual
            - El mes actual
            - El dia actual
            - La hora actual

        Todos estos datos de tiempo del tiempo universal condinado +0 ó UTC±0.

        Esta concatenación se encriptará usando md5.
        '''
        t = gmtime()
        return md5(f'{conexion.getUsuario()}{conexion.getClave()}{randomInt}{t[0]}{t[1]}{t[2]}{t[3]}'.encode('utf-8')).hexdigest()

    def Mt1(self):
        return DTM(
            states = {'q0', 'q1'},
            input_symbols = {
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', '0', '.', '-', ',', ' '},
             tape_symbols={
                'B', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', '0', '.', '-', ',', ' '},
             transitions={
                'q0': {
                    'a': ('q0', 'b', 'R'),
                    'b': ('q0', 'c', 'R'),
                    'c': ('q0', 'd', 'R'),
                    'd': ('q0', 'e', 'R'),
                    'e': ('q0', 'f', 'R'),
                    'f': ('q0', 'g', 'R'),
                    'g': ('q0', 'h', 'R'),
                    'h': ('q0', 'i', 'R'),
                    'i': ('q0', 'j', 'R'),
                    'j': ('q0', 'k', 'R'),
                    'k': ('q0', 'l', 'R'),
                    'l': ('q0', 'm', 'R'),
                    'm': ('q0', 'n', 'R'),
                    'n': ('q0', 'o', 'R'),
                    'o': ('q0', 'p', 'R'),
                    'p': ('q0', 'q', 'R'),
                    'q': ('q0', 'r', 'R'),
                    'r': ('q0', 's', 'R'),
                    's': ('q0', 't', 'R'),
                    't': ('q0', 'u', 'R'),
                    'u': ('q0', 'v', 'R'),
                    'v': ('q0', 'w', 'R'),
                    'w': ('q0', 'x', 'R'),
                    'x': ('q0', 'y', 'R'),
                    'y': ('q0', 'z', 'R'),
                    'z': ('q0', 'a', 'R'),
                    '0': ('q0', '1', 'R'),
                    '1': ('q0', '2', 'R'),
                    '2': ('q0', '3', 'R'),
                    '3': ('q0', '4', 'R'),
                    '4': ('q0', '5', 'R'),
                    '5': ('q0', '6', 'R'),
                    '6': ('q0', '7', 'R'),
                    '7': ('q0', '8', 'R'),
                    '8': ('q0', '9', 'R'),
                    '9': ('q0', '0', 'R'),
                    '.': ('q0', ',', 'R'),
                    ',': ('q0', '-', 'R'),
                    '-': ('q0', ' ', 'R'),
                    ' ': ('q0', '.', 'R'),
                    'B': ('q1', 'B', 'R')
                }
             },
             initial_state='q0',
             blank_symbol='B',
             final_states={'q1'}
        )

    def Mt2(self):
        return DTM(
            states = {'q0', 'q1'},
            input_symbols = {
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', '0', '.', '-', ',', ' '
            },
            tape_symbols = {
                'B', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', '0', '.', '-', ',', ' '
            },
            transitions = {
                'q0': {
                    'a': ('q0', 'z', 'R'),
                    'b': ('q0', 'a', 'R'),
                    'c': ('q0', 'b', 'R'),
                    'd': ('q0', 'c', 'R'),
                    'e': ('q0', 'd', 'R'),
                    'f': ('q0', 'e', 'R'),
                    'g': ('q0', 'f', 'R'),
                    'h': ('q0', 'g', 'R'),
                    'i': ('q0', 'h', 'R'),
                    'j': ('q0', 'i', 'R'),
                    'k': ('q0', 'j', 'R'),
                    'l': ('q0', 'k', 'R'),
                    'm': ('q0', 'l', 'R'),
                    'n': ('q0', 'm', 'R'),
                    'o': ('q0', 'n', 'R'),
                    'p': ('q0', 'o', 'R'),
                    'q': ('q0', 'p', 'R'),
                    'r': ('q0', 'q', 'R'),
                    's': ('q0', 'r', 'R'),
                    't': ('q0', 's', 'R'),
                    'u': ('q0', 't', 'R'),
                    'v': ('q0', 'u', 'R'),
                    'w': ('q0', 'v', 'R'),
                    'x': ('q0', 'w', 'R'),
                    'y': ('q0', 'x', 'R'),
                    'z': ('q0', 'y', 'R'),
                    '0': ('q0', '9', 'R'),
                    '1': ('q0', '0', 'R'),
                    '2': ('q0', '1', 'R'),
                    '3': ('q0', '2', 'R'),
                    '4': ('q0', '3', 'R'),
                    '5': ('q0', '4', 'R'),
                    '6': ('q0', '5', 'R'),
                    '7': ('q0', '6', 'R'),
                    '8': ('q0', '7', 'R'),
                    '9': ('q0', '8', 'R'),
                    '.': ('q0', ' ', 'R'),
                    ',': ('q0', '.', 'R'),
                    '-': ('q0', ',', 'R'),
                    ' ': ('q0', '-', 'R'),
                    'B': ('q1', 'B', 'R')
                }
            },
            initial_state='q0',
            blank_symbol='B',
            final_states={'q1'}
        )

    def useMT(self, mt, token, msg):
        for i in range(int(token,base=16)%26):
            msg = ''.join(mt.validate_input(msg)[1].tape).replace('B', '')
        return msg

    def sendDataToConns(self, dataFromConn):
        '''
        Metodo encargado de enviar informacion a las conexiones

        Parametros:
            - dataFromConn: dict

        Primero se procederá a iterar en las conexiones revisando si la
        conexion está autenticada, de ser asi se generará un paquete
        personalizado con el token de dicha conexion y los datos recibidos
        de la conexion entrante y se procederá a enviar, en caso de que no
        se pueda enviar el paquete se procederá a desconectar dicha conexion.
        '''
        desconectar = []
        for conexion in self.conexiones:
            if conexion.getIsAuth():
                if dataFromConn['type'] == 'msg':
                    msg = self.useMT(self.mt2, dataFromConn['payload']['token'], dataFromConn['payload']['msg'])
                    data = {
                        'type': 'msg',
                        'payload': {
                            'token': self.doMd5(conexion.getToken()),
                            'user': dataFromConn['payload']['user'],
                            'msg': self.useMT(self.mt1, conexion.getToken(), msg),
                            'time': dataFromConn['payload']['time']
                        }
                    }
                elif dataFromConn['type'] == 'changeSettings':
                    data = {
                        'type': 'changeSettings',
                        'payload': {
                            'token': self.doMd5(conexion.getToken()),
                            'colores': self.getColores()
                        }
                    }
                try:
                    conexion.send(f'{data}')
                except:
                    desconectar.append(self.conexiones.index(conexion))
        for i in desconectar:
            self.disconnectConn(i)

    def info(self):
        '''
        Metodo encargado de imprimir informacion en la terminal del servidor
        '''
        print('{} {} Numero de conexiones: {} numero de threads: {}'.format(self.INFO,self.getTime(),len(self.conexiones),len(self.threads)),end='\r')

    def getTime(self):
        '''
        Metodo encargado de obtener el tiempo local del servidor
        '''
        currentTime = localtime()
        return '[{:02}:{:02}]'.format(currentTime[3],currentTime[4])

    def getInfoType(self,msg,code):
        '''
        Metodo encargado de formatear el tipo de informacion segun el codigo
        de su color
        '''
        return '[\033[{}m{}\033[0m]'.format(code,msg.center(4))

    def getColores(self):
        '''
        Metodo encargado de devolver un diccionario con el color almacenado de
        cada usuario
        '''
        data = {}
        for user, value in self.datos.items():
            data[user] = value['color']
        return data

    def setColores(self, user, color):
        '''
        Metodo encargado de cambiar el color de un usuario

        Parametros:
            - user: str
            - color: str

        Se buscará dentro de las conexiones el usuario indicado y se cambiará
        el atributo color de dicha conexion y se actualizará el archivo
        datos.json
        '''
        for conexion in self.conexiones:
            if conexion.getUsuario() == user:
                conexion.setColor(color)
                self.datos[user]['color'] = color
                dump(self.datos, open('datos.json','w'), indent=4)
                break
    def doMd5(self, text):
        return md5(text.encode('utf8')).hexdigest()


class Conexion():
    '''
    Clase encargada del manejo de una conexion
    '''
    def __init__(self, conn, addr):
        self.connected = True
        self.conn = conn
        self.addr = addr
        self.isAuth = False
        self.color = '#00ad5f'
        self.token = ''

    def login(self):
        rawData = self.recv()
        if rawData:
            data = loads(rawData)
            if data['type'] == 'login':
                self.user = data['payload']['user']
                self.password = data['payload']['password']
                return (self.user, self.password)
        else:
            return '',''

    def setThread(self,thread):
        self.thread = thread

    def getThread(self):
        return self.thread

    def send(self,msg):
        size = '{:05}'.format(len(msg))
        try:
            self.conn.send(size.encode())
            self.conn.send(msg.encode())
        except:
            self.disconnected()

    def recv(self):
        try:
            size = self.conn.recv(5).decode()
            if size:
                size = int(size)
                data = self.conn.recv(size).decode('utf-8').replace('\'','"')
                return data
            else:
                return None
        except error:
            self.disconnected()

    def isConnected(self):
        return self.connected

    def disconnected(self):
        self.connected = False

    def getAddr(self):
        return self.addr

    def getIsAuth(self):
        return self.isAuth

    def setIsAuth(self):
        self.isAuth = True

    def getUsuario(self):
        return self.user

    def getClave(self):
        return self.password

    def setColor(self, color):
        self.color = color

    def getColor(self):
        return self.color

    def setToken(self, token):
        self.token = token

    def getToken(self):
        return self.token

if __name__ == '__main__':
    server = Server('0.0.0.0',24051)
    while True:
        server.info()
        sleep(5)
