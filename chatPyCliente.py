'''
Modulo chatPyClient.py

Proyecto final de automatas y lenguajes formales

Realizado por:
    Laura Jaimes
    Diego Landinez
    Edwar Plata

Implementado por:
    Edwar Plata
'''

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from time import sleep, gmtime, localtime
from sys import exit
from hashlib import md5, sha256
from getpass import getpass
from os import get_terminal_size, system
from json import loads
from tkinter import Tk, Label, Entry, Frame, END, INSERT, messagebox, LabelFrame, Text, Toplevel, Menu
from tkinter.colorchooser import askcolor
from tkinter.scrolledtext import ScrolledText
from automata.tm.dtm import DTM
from pprint import pprint

class ChatGui():
    '''
    Clase para la interfaz grafica del chat.
    '''
    def __init__(self, main):
        self.main = main
        self.alfabeto = self.main.getAlfabeto()

    def start(self):
        self.root = Tk()
        self.main.startThreads()
        self.root.resizable(False, False)
        self.root.title('ChatPy')
        self.root.geometry('350x500')
        self.app = Frame(bg='#000000')
        self.app.pack()
        self.menu = Menu(self.app, bg='#111111', borderwidth=0, foreground='#ffffff', font=('Open Sans', 10), activebackground='#191919', activeforeground='#ffffff')
        self.root.config(menu=self.menu)
        accountMenu = Menu(self.menu, tearoff=0, bg='#111111', borderwidth=0, foreground='#ffffff', font=('Open Sans', 10), activebackground='#191919', activeforeground='#ffffff')
        accountMenu.add_command(label='Cerrar', command=lambda: exit())
        settingsMenu = Menu(self.menu, tearoff=0, bg='#111111', borderwidth=0, foreground='#ffffff', font=('Open Sans', 10), activebackground='#191919', activeforeground='#ffffff')
        settingsMenu.add_command(label='Cambiar color', command=lambda: self.cambiarColor())
        self.menu.add_cascade(label='Conexion', menu=accountMenu)
        self.menu.add_cascade(label='Ajustes', menu=settingsMenu)
        self.userInput = Entry(self.app, width=300, bg='#111111', borderwidth=0, foreground='snow', highlightthickness=0,insertbackground='#00ad5f', font=('Open Sans', 10))
        self.userInput.pack(side='bottom', fill='x')
        self.root.after(1, lambda: self.root.focus_force())
        self.userInput.focus()
        self.history = Text(self.app, width=300, height=290, state='disabled',bg='#191919', borderwidth=0, foreground='snow', highlightthickness=0, font=('Open Sans',10))
        self.history.pack(side='top')
        # self.history.bindtags((f'{self.history}', f'{self.root}', "all"))
        self.history.bind('<Button-1>', self.userInput.focus())
        self.root.bind('<Return>', self.getInput)
        # self.root.protocol("WM_DELETE_WINDOW", self.onClosing)
        self.root.mainloop()

    def cambiarColor(self):
        color_one = HEXToRGB('#191919')
        color_two = askcolor()
        light = color_one if sum(color_one) > sum(color_two[0]) else color_two[0]
        dark = color_one if sum(color_one) < sum(color_two[0]) else color_two[0]
        contrast_ratio = ( calculate_relative_luminance(light) + 0.05 ) / ( calculate_relative_luminance(dark) + 0.05 )
        print(contrast_ratio)
        if contrast_ratio < 7:
            self.print({'time': self.main.getTime(), 'user': '', 'msg': 'Ese color no está permitido intente con otro.'})
        else:
            data = {
                'type': 'changeSettings',
                'payload': {
                    'token': self.main.getToken(),
                    'user': self.main.getUser(),
                    'color': color_two[1]
                }
            }
            self.main.send(f'{data}')

    def getInput(self, event):
        data = self.userInput.get().replace('ñ','n')
        data = data.lower()
        valido = True
        if data:
            self.clearInput()
            for caracter in data:
                if caracter not in self.alfabeto:
                    self.print({'time': self.main.getTime(), 'user': '', 'msg': 'Hay un carácter no permitido en tu mensaje!'})
                    valido = False
                    break
        if valido:
            self.main.sendMsg(data)

    def clearInput(self):
        self.userInput.delete(0, END)

    def print(self, data):
        self.history.config(state='normal')
        self.history.insert(END, f'{data["time"]}', 'time')
        if not data['user']:
            self.history.insert(END, f' {data["msg"]}\n', 'warning')
            self.history.tag_config('warning', foreground='#ff0000')
        else:
            self.history.insert(END, f' {data["user"]}: ', f'{data["user"]}')
            self.history.insert(END, f'{data["msg"]}\n', 'data')
        if data['user']:
            self.history.tag_config(data['user'], foreground=self.main.getColor(data['user']))
        self.history.tag_config('time', foreground='#cccccc', font=('Open Sans',8))
        self.history.yview(END)
        self.history.config(state='disabled')

    def onClosing(self):
        if messagebox.askokcancel('Desconectar', '¿Seguro que deseas salir?'):
            self.root.destroy()

class LoginGui():
    '''
    Clase para la interfaz grafica del login
    '''
    def __init__(self, main):
        self.main = main
        self.root = Tk()
        self.root.title('Login')
        # self.root.geometry('200x100')
        self.root.config(bg='#191919')
        self.root.resizable(False, False)
        self.loginFrame = Frame(self.root, bg='#191919')
        self.loginFrame.pack(side='top',padx=5, pady=10)
        labelLogin = Label(self.loginFrame, text='Usuario:',bg='#191919', foreground='#00ad5f')
        labelLogin.grid(column=0, row=0, padx=4, pady=4)
        self.userInput = Entry(self.loginFrame,bg='#111111', borderwidth=0, foreground='snow', highlightthickness=0,insertbackground='#00ad5f', font=(None, 12), width=14)
        self.userInput.grid(column=1, row=0, padx=4, pady=4)
        self.userInput.focus()
        labelClave = Label(self.loginFrame, text='Clave:',bg='#191919', foreground='#00ad5f')
        labelClave.grid(column=0, row=1, padx=4, pady=4)
        self.claveInput = Entry(self.loginFrame, show='*',bg='#111111', borderwidth=0, foreground='snow', highlightthickness=0,insertbackground='#00ad5f', font=(None, 12), width=14)
        self.claveInput.grid(column=1, row=1, padx=4, pady=4)
        self.infoLabel = Label(self.loginFrame, text='', bg='#191919')
        self.infoLabel.grid(column=0, row=2, columnspan=2)
        self.root.bind('<Return>', self.getLogin)
        self.attempt = 0
        self.root.mainloop()

    def getLogin(self, event):
        if self.attempt < 3:
            self.user = self.userInput.get().replace('ñ','n').replace('Ñ','N')
            self.clave = self.claveInput.get().replace('ñ','n').replace('Ñ','N')
            if '\'' not in self.user and '"' not in self.user and '\'' not in self.clave and '"' not in self.clave and '´' not in self.clave and self.main.login(self.user,self.clave):
                self.infoLabel.config(text='Autenticado', foreground='green')
                self.infoLabel.after(2000, lambda: self.root.destroy())
            else:
                self.userInput.delete(0,END)
                self.claveInput.delete(0,END)
                self.userInput.focus()
                self.infoLabel.config(text='Usuario o clave invalidos', foreground='red')
                self.attempt += 1
        else:
            exit()

    def getCredentials(self):
        return self.user, self.clave

class Client():
    def __init__(self, ip: str, port: int):
        self.ip, self.port, self.client = ip, port, socket(AF_INET, SOCK_STREAM)
        print('Iniciando {}:{}'.format(self.ip,self.port))
        self.client.connect((self.ip,self.port))
        self.client.settimeout(None)
        self.threads = [
            Thread(target=self.getDataFromServer, daemon=True)
        ]
        self.token = ''
        self.mt1 = self.Mt1()
        self.mt2 = self.Mt2()
        login = LoginGui(self)
        if self.authenticated:
            self.chat = ChatGui(self)
            self.chat.start()

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

    def getDataFromServer(self):
        while True:
            rawDataFromServer = self.recv()
            if not rawDataFromServer:
                exit()
            dataFromServer = loads(rawDataFromServer)
            if dataFromServer['type'] == 'msg' and dataFromServer['payload']['token'] == self.getToken():
                data = {
                    'time': dataFromServer['payload']['time'],
                    'user': dataFromServer['payload']['user'],
                    'msg': self.useMT(self.mt2, dataFromServer['payload']['msg'])
                }
                self.chat.print(data)
            elif dataFromServer['type'] == 'changeSettings' and dataFromServer['payload']['token'] == self.getToken():
                print('Alguien a cambiado sus ajustes')
                self.setColores(dataFromServer['payload']['colores'])
            else:
                exit()

    def login(self,user,password,attempt = 1):
        if attempt <= 3:
            data = {}
            data['type'] = 'login'
            data['payload'] = {}
            data['payload']['user'] = user
            self.user = user
            self.password = sha256(password.encode('utf-8')).hexdigest()
            data['payload']['password'] = self.password
            self.send(f'{data}')
            auth = self.recv()
            dataFromServer = loads(auth)
            if dataFromServer['type'] == 'auth':
                if dataFromServer['payload']['authenticated']:
                    self.setToken(self.generateToken(dataFromServer['payload']['secret']))
                else:
                    self.authenticated = False
                    return False
            data = {}
            data['type'] = 'checkToken'
            data['payload'] = {}
            data['payload']['token'] = self.getToken()
            self.send(f'{data}')
            checkToken = self.recv()
            dataFromServer = loads(checkToken)
            if dataFromServer['type'] == 'checkToken':
                if not dataFromServer['payload']['correctToken']:
                    print('El token es invalido.')
                    self.login(user,password,attempt+1)
                else:
                    self.authenticated = True
                    getColores = self.recv()
                    dataFromServer = loads(getColores)
                    if dataFromServer['type'] == 'getColores':
                        self.colores = dataFromServer['payload']
                    return True

        else:
            exit()

    def sendMsg(self, msg):
        msg = self.useMT(self.mt1, msg)
        data = {
            'type': 'msg',
            'payload': {
                'token': self.getToken(),
                'time': self.getTime(),
                'msg': msg,
                'user': self.user
            }
        }
        self.send(f'{data}')

    def useMT(self, mt, msg):
        token = self.getToken()
        for i in range(int(token,base=16)%26):
            msg = ''.join(mt.validate_input(msg)[1].tape).replace('B', '')
        return msg

    def send(self,msg):
        print(f'Enviando: {msg}')
        size = '{:05}'.format(len(msg))
        self.client.send(size.encode())
        self.client.send(msg.encode())

    def recv(self):
        size = self.client.recv(5).decode()
        if size:
            size = int(size)
            return self.client.recv(size).decode('utf-8').replace('\'','"')
        else:
            return None

    def generateToken(self, randomInt):
        t = gmtime()
        return md5(f'{self.user}{self.password}{randomInt}{t[0]}{t[1]}{t[2]}{t[3]}'.encode('utf-8')).hexdigest()

    def setToken(self, token):
        self.token = token

    def getToken(self):
        return self.token

    def getTime(self):
        currentTime = localtime()
        return '[{:02}:{:02}]'.format(currentTime[3],currentTime[4])

    def startThreads(self):
        for thread in self.threads:
            thread.start()

    def getUser(self):
        return self.user

    def getColor(self, user):
        return self.colores[user]

    def setColores(self, data):
        self.colores = data

    def getAlfabeto(self):
        return {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
            'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', '0', '.', '-', ',', ' '
            }

def HEXToRGB(value):
    value = value.lstrip('#')
    lv = len(value)
    return tuple(int(value[i:i + lv // 3], 16) for i in range(0, lv, lv // 3))

def RGBToHEX(rgb):
    return '#%02x%02x%02x' % rgb

def calculate_luminace(color_code):
    index = float(color_code) / 255
    if index < 0.03928:
        return index / 12.92
    else:
        return ( ( index + 0.055 ) / 1.055 ) ** 2.4

def calculate_relative_luminance(rgb):
    return 0.2126 * calculate_luminace(rgb[0]) + 0.7152 * calculate_luminace(rgb[1]) + 0.0722 * calculate_luminace(rgb[2])

if __name__ == '__main__':
    client = Client('localhost',24051)
