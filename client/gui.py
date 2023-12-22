import json
import os
import base64
import datetime
import logging
import binascii
import os
import time
import xml.etree.ElementTree as ET
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QDesktopWidget, QSpacerItem, QSizePolicy, QTextEdit, QListWidgetItem, QListWidget, QHBoxLayout, QFileDialog, QMenu, QAction, QToolButton
from PyQt5.QtCore import pyqtSignal, Qt, QUrl, QByteArray, QEventLoop, QTimer, QSize, QPoint
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from PyQt5.QtGui import QFont, QColor, QPixmap
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from functools import partial
from threading import Semaphore

class User:
    def __init__(self):
        self.username = None
        self.is_authenticated = False
        self.conversation_partner = None

    def login(self, username):
        self.username = username
        self.is_authenticated = True

    def logout(self):
        self.username = None
        self.is_authenticated = False
        self.conversation_partner = None
    
    def start_conversation(self, partner_username):
        self.conversation_partner = partner_username  # Stocarea numelui de utilizator al partenerului de conversație

    def end_conversation(self):
        self.conversation_partner = None  # Ștergerea numelui de utilizator al partenerului

user = User()
sem = Semaphore()

class LoginWindow(QWidget):
    showRegistrationWindow = pyqtSignal()
    showHomeWindow = pyqtSignal()

    def __init__(self, home_window):
        super().__init__()
        self.home_window = home_window

        # Setează dimensiunile dorite pentru fereastră
        window_width = 600
        window_height = 700
        self.resize(window_width, window_height)

        self.setWindowTitle("QuickChat - Login")
        self.layout = QVBoxLayout()
        self.layout.addSpacing(100)

        self.label_title = QLabel("Welcome to QuickChat!")  # Adaugă titlul
        self.label_title.setFont(QFont('Times', 18))  # Schimbă fontul și dimensiunea textului
        self.label_title.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label_title)

        self.label_subtitle = QLabel("Log in into your account right now!")  # Adaugă subtitlul
        self.label_subtitle.setFont(QFont('Times', 12))  # Schimbă fontul și dimensiunea textului
        self.label_subtitle.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label_subtitle)

        self.layout.addSpacing(100)

        self.label_username = QLabel("Username:")
        self.label_username.setFont(QFont('KBZipaDeeDooDah', 10))  # Schimbă fontul și dimensiunea textului
        self.entry_username = QLineEdit()
        self.entry_username.setFont(QFont('KBZipaDeeDooDah', 8))  # Schimbă fontul și dimensiunea textului

        self.label_password = QLabel("Password:")
        self.label_password.setFont(QFont('Times', 10))  # Schimbă fontul și dimensiunea textului
        self.entry_password = QLineEdit()
        self.entry_password.setFont(QFont('Times', 8))  # Schimbă fontul și dimensiunea textului
        self.entry_password.setEchoMode(QLineEdit.Password)

        self.button_login = QPushButton("Login")
        self.button_login.setFont(QFont('Times', 8))  # Schimbă fontul și dimensiunea textului
        self.button_login.setStyleSheet("background-color: #2fa190; color: white;")  # Adaugă culoare butonului
        self.button_login.clicked.connect(self.authenticate_user)

        self.button_no_account = QPushButton("Don't have an account? Create one right now!")
        self.button_no_account.setFont(QFont('Times', 8))  # Schimbă fontul și dimensiunea textului
        self.button_no_account.setStyleSheet("background-color: #2E7267; color: white;")  # Adaugă culoare butonului
        self.button_no_account.clicked.connect(self.show_registration_window)

        self.layout.addWidget(self.label_username)
        self.layout.addWidget(self.entry_username)
        self.layout.addWidget(self.label_password)
        self.layout.addWidget(self.entry_password)
        self.layout.addWidget(self.button_login)
        self.layout.addWidget(self.button_no_account)

        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))  # Adaugă spațiere în partea de jos

        self.setLayout(self.layout)

    def authenticate_user(self):
        username = self.entry_username.text()
        password = self.entry_password.text()

        if not username or not password:
            QMessageBox.critical(self, "Error", "Both fields must be filled in!")
        else:
            # Creează un manager de acces la rețea
            network_manager = QNetworkAccessManager(self)
            
            # Construiește URL-ul pentru autentificare
            url = QUrl("http://localhost:5000/authenticate_user")
            
            # Construiește cererea
            request = QNetworkRequest(url)
            request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
            
            # Construiește datele JSON pentru autentificare
            data = {"username": username, "password": password}
            
            # Creează și trimite cererea POST
            reply = network_manager.post(request, QByteArray(json.dumps(data).encode('utf-8')))
            
            # Conectează slot-ul de răspuns la cerere
            reply.finished.connect(self.handle_authentication_response)
        
        self.entry_username.setText('')
        self.entry_password.setText('')
    
    def handle_authentication_response(self):
        reply = self.sender()
        response_data = json.loads(reply.readAll().data().decode('utf-8'))
        message = response_data.get('message', '')

        if message == "User authenticated successfully":
            QMessageBox.information(self, "Succes", message)
            username = response_data.get('username', '')
            user.login(username)

            self.home_window.check_user()
            self.showHomeWindow.emit()
            self.hide()
        else:
            QMessageBox.critical(self, "Error", message)

    def show_registration_window(self):
        self.showRegistrationWindow.emit()
        self.hide()

class RegistrationWindow(QWidget):
    showLoginWindow = pyqtSignal()

    def __init__(self):
        super().__init__()

        window_width = 600
        window_height = 700
        self.resize(window_width, window_height)

        self.setWindowTitle("QuickChat - Create New Account")
        self.layout = QVBoxLayout()
        self.layout.addSpacing(100)

        self.label_title = QLabel("Create a new account right now!")  # Adaugă titlul
        self.label_title.setFont(QFont('Times', 18))  # Schimbă fontul și dimensiunea textului
        self.label_title.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label_title)

        self.layout.addSpacing(140)

        self.label_username = QLabel("Username:")
        self.entry_username = QLineEdit()

        self.label_password = QLabel("Password:")
        self.entry_password = QLineEdit()
        self.entry_password.setEchoMode(QLineEdit.Password)

        self.label_repassword = QLabel("Re-enter password:")
        self.entry_repassword = QLineEdit()
        self.entry_repassword.setEchoMode(QLineEdit.Password)

        self.button_create_acc = QPushButton("Create your account now!")
        self.button_create_acc.setStyleSheet("background-color: #2fa190; color: white;")  # Adaugă culoare butonului
        self.button_create_acc.clicked.connect(self.create_account)

        self.button_login = QPushButton("Go to Login Page!")
        self.button_login.setStyleSheet("background-color: #2E7267; color: white;")  # Adaugă culoare butonului
        self.button_login.clicked.connect(self.show_login_window)

        self.layout.addWidget(self.label_username)
        self.layout.addWidget(self.entry_username)
        self.layout.addWidget(self.label_password)
        self.layout.addWidget(self.entry_password)
        self.layout.addWidget(self.label_repassword)
        self.layout.addWidget(self.entry_repassword)
        self.layout.addWidget(self.button_create_acc)
        self.layout.addWidget(self.button_login)

        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.setLayout(self.layout)
    
    def create_account(self):

        username = self.entry_username.text()
        password = self.entry_password.text()
        repassword = self.entry_repassword.text()

        if not username or not password or not repassword:
            QMessageBox.critical(self, "Error", "All fields must be filled in!")
        elif password != repassword:
            QMessageBox.critical(self, "Error", "Passwords must match!")
        elif username == password and username == repassword:
            QMessageBox.critical(self, "Error", "The password must not match with the username!")
        else:
            # Creează un manager de acces la rețea
            network_manager = QNetworkAccessManager(self)
            
            # Construiește URL-ul pentru autentificare
            url = QUrl("http://localhost:5000//create_user")
            
            # Construiește cererea
            request = QNetworkRequest(url)
            request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
            
            # Construiește datele JSON pentru autentificare
            data = {"username": username, "password": password}
            
            # Creează și trimite cererea POST
            reply = network_manager.post(request, QByteArray(json.dumps(data).encode('utf-8')))
            
            # Conectează slot-ul de răspuns la cerere
            reply.finished.connect(self.handle_create_account_response)

    def handle_create_account_response(self):
        reply = self.sender()
        response_data = json.loads(reply.readAll().data().decode('utf-8'))
        message = response_data.get('message', '')

        if message == "User created successfully!":
            QMessageBox.information(self, "Succes", message)

            self.showLoginWindow.emit()
            self.hide()
        else:
            QMessageBox.critical(self, "Error", message)

    def show_login_window(self):
        self.showLoginWindow.emit()
        self.hide()

class HomeWindow(QWidget):
    showConversationWindow = pyqtSignal()
    showLoginWindow = pyqtSignal()

    def __init__(self, conversation_window):
        super().__init__()
        self.conversation_window = conversation_window

    def check_user(self):
       
        window_width = 600
        window_height = 700
        self.resize(window_width, window_height)

        self.setWindowTitle("QuickChat - Home")
        
        if self.layout is not None:
            if isinstance(self.layout, QVBoxLayout):
                while self.layout.count():
                    child = self.layout.takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
            else:
                self.layout = QVBoxLayout()
        else:
            self.layout = QVBoxLayout()
        
        self.layout.addSpacing(120)

        print("username:", user.username, "\n")

        self.label_welcome = QLabel(f"Welcome, {user.username}!")  # Adaugă mesajul de bun venit
        self.label_welcome.setFont(QFont('Times', 18))  # Schimbă fontul și dimensiunea textului
        self.label_welcome.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label_welcome)

        self.layout.addSpacing(20)

        self.label_prompt = QLabel("Enter the name of the user you want to start a new conversation with!")  # Adaugă prompt-ul
        self.label_prompt.setFont(QFont('Times', 12))  # Schimbă fontul și dimensiunea textului
        self.label_prompt.setAlignment(Qt.AlignCenter)
        self.label_prompt.setWordWrap(True)  # Permite înfășurarea cuvintelor
        self.layout.addWidget(self.label_prompt)

        self.layout.addSpacing(120)

        self.entry_username = QLineEdit()  # Adaugă câmpul pentru introducerea numelui de utilizator

        self.button_start_conversation = QPushButton("Start a conversation!")  # Adaugă butonul pentru începerea unei conversații
        self.button_start_conversation.setStyleSheet("background-color: #2fa190; color: white;")  # Adaugă culoare butonului
        self.button_start_conversation.clicked.connect(self.start_conversation)

        self.layout.addWidget(self.entry_username)
        self.layout.addWidget(self.button_start_conversation)

        self.button_logout = QPushButton("Logout")  # Adăugați un nou buton pentru logout
        self.button_logout.clicked.connect(self.logout)  # Conectați semnalul clicked la metoda de logout
        self.layout.addWidget(self.button_logout)  # Adăugați butonul la layout

        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))  # Adaugă spațiere în partea de jos

        self.setLayout(self.layout)

    def start_conversation(self):
        username = self.entry_username.text()
        print("Start conversation with: ", username, "\n")

        if not username:
            QMessageBox.critical(self, "Error", "Username field must be filled in!")
        else:
            # Creează un manager de acces la rețea
            network_manager = QNetworkAccessManager(self)
            
            # Construiește URL-ul pentru autentificare
            url = QUrl("http://localhost:5000/check_username")
            
            # Construiește cererea
            request = QNetworkRequest(url)
            request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
            
            # Construiește datele JSON pentru autentificare
            data = {"my_username": user.username, "username": username}
            
            # Creează și trimite cererea POST
            reply = network_manager.post(request, QByteArray(json.dumps(data).encode('utf-8')))
            
            # Conectează slot-ul de răspuns la cerere
            reply.finished.connect(self.handle_conversation_response)

    def handle_conversation_response(self):
        reply = self.sender()
        response_data = json.loads(reply.readAll().data().decode('utf-8'))
        message = response_data.get('message', '')

        if message == "Username exists":
            # QMessageBox.information(self, "Succes", message)
            username = response_data.get('username', '')
            user.start_conversation(username)

            self.conversation_window.conversation()
            self.showConversationWindow.emit()
            self.hide()
        else:
            QMessageBox.critical(self, "Error", message)

    def logout(self):
        user.logout()
        self.showLoginWindow.emit()
        self.hide()

class ConversationWindow(QWidget):
    key_received = pyqtSignal()
    showHomeWindow = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.key = None 
        self.last_sent_date = None
        self.message_display = QListWidget()

    def conversation(self):
        sorted_usernames = sorted([user.username, user.conversation_partner])

        # Generează numele fișierului
        log_filename = f'{sorted_usernames[0]}-{sorted_usernames[1]}.log'

        # grafica
        window_width = 600
        window_height = 700
        self.resize(window_width, window_height)

        self.setWindowTitle(f"QuickChat - Conversation with {user.conversation_partner}")

        if self.layout is not None:
            if isinstance(self.layout, QVBoxLayout):
                while self.layout.count():
                    child = self.layout.takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
            else:
                self.layout = QVBoxLayout()
        else:
            self.layout = QVBoxLayout()


        # Creați un QHBoxLayout pentru butoane
        button_layout = QHBoxLayout()

        # Adăugați butonul "Back" în partea stângă
        button_back = QPushButton("Back")
        button_back.clicked.connect(self.back)  # Conectați-l la metoda "back"
        button_layout.addWidget(button_back)

        # Adăugați un spațiu gol pentru a împinge celălalt buton în partea dreaptă
        button_layout.addStretch()

        # Adăugați butonul "Delete Conversation" în partea dreaptă
        button_delete = QPushButton("Delete Conversation")
        button_delete.clicked.connect(partial(self.delete_conversation,f'logs/{log_filename}'))  # Conectați-l la metoda "delete_conversation"
        button_layout.addWidget(button_delete)

        # Adăugați layout-ul de butoane la layout-ul principal
        self.layout.addLayout(button_layout)

        # Adăugați un widget de afișare a mesajelor
        self.message_display = QListWidget()
        # self.message_display.setReadOnly(True)
        self.layout.addWidget(self.message_display)
        self.message_display.clear()

        # Adăugați un widget de introducere a mesajelor
        self.message_entry = QLineEdit()
        self.layout.addWidget(self.message_entry)

        # Creați un nou QPushButton pentru emoji-uri
        self.button_emoji = QPushButton("Emoji")
        # self.layout.addWidget(self.button_emoji)
        self.button_emoji.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)

        # Creați un QMenu pentru a afișa emoji-urile
        self.emoji_menu = QMenu(self)

        # Adăugați câteva emoji-uri în meniu
        for emoji in ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😇', '😍', '😘', '😗', '😚', '😙', '😋', '😛', '😜', '😝', '🤑', '🤗', '🤓', '😎', '🤡', '🤠', '😏', '😒', '😞', '😔', '😟', '😕', '🙁', '☹️', '😣', '😖', '😫', '😩', '😤', '😠', '😡', '😶', '😐', '😑', '😯', '😦', '😧', '😮', '😲', '😵', '😳', '😱', '😨', '😰', '😢', '😥', '🤤', '😭', '😓', '😪', '😴', '🙄', '🤔', '🤥', '😬', '🤐', '🤢', '🤧', '😷', '🤒', '🤕', '😈', '👿', '👹', '👺', '💩', '👻', '💀', '☠️', '👽', '👾', '🤖', '🎃', '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾']:
            action = QAction(emoji, self)
            action.triggered.connect(lambda checked, e=emoji: self.insert_emoji(e))
            self.emoji_menu.addAction(action)

        # Conectați butonul de emoji-uri la meniul de emoji-uri
        self.button_emoji.clicked.connect(lambda: self.emoji_menu.popup(self.button_emoji.mapToGlobal(QPoint(0,0))))

        # Definește butonul de trimitere a mesajelor
        self.button_start_conversation = QPushButton("Send")
        self.button_start_conversation.setEnabled(False)  # Dezactivează butonul inițial
        self.button_start_conversation.clicked.connect(partial(self.send_message, f'logs/{log_filename}'))
        self.button_start_conversation.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # Activează butonul de trimitere atunci când există text în widget-ul de introducere a mesajelor
        self.message_entry.textChanged.connect(lambda: self.button_start_conversation.setEnabled(bool(self.message_entry.text())))
        # self.layout.addWidget(self.button_start_conversation)

        # Creați un QHBoxLayout pentru a pune butoanele pe același rând
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.button_start_conversation)
        button_layout.addWidget(self.button_emoji)

        self.layout.addLayout(button_layout)

        self.button_upload_image = QPushButton("Upload Image")
        self.button_upload_image.clicked.connect(partial(self.upload_image, f'logs/{log_filename}'))
        self.layout.addWidget(self.button_upload_image)

        self.setLayout(self.layout)

        # creare fisier log / incarcare mesaje din fisier /
        if not os.path.exists(f'logs/{log_filename}'):
            print("Creaza fisier log:", f'logs/{log_filename}')
            with open(f'logs/{log_filename}', 'w') as f:
                pass

            # Generarea unei chei de criptare
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)

            # Convertirea cheii într-un șir
            key_str = key.decode()

            # salvarea key-ul in database
            network_manager = QNetworkAccessManager(self)
            url = QUrl("http://localhost:5000/store_key")
            request = QNetworkRequest(url)
            request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
            data = {"username1": user.username, "username2": user.conversation_partner, "key": key_str}
            reply = network_manager.post(request, QByteArray(json.dumps(data).encode('utf-8')))

            # Conectează slot-ul de răspuns la cerere
            reply.finished.connect(partial(self.handle_create_key, log_filename))
        else:
            print("Incarca mesaje din fisier:", f'logs/{log_filename}')
            self.load_messages_from_xml(f'logs/{log_filename}')

        self.my_class_instance = ConversationWindow.MyClass(f'logs/{log_filename}', self)
        self.timer = QTimer()
        self.timer.timeout.connect(partial(self.my_class_instance.verify_is_modified))
        self.timer.start(1000)  # timpul este în milisecund

    def insert_emoji(self, emoji):
        self.message_entry.insert(emoji)

    def upload_image(self, log_filename):
        # Deschideți un dialog pentru a selecta fișierul imagine
        image_filename, _ = QFileDialog.getOpenFileName()

        if image_filename:
            # Dacă un fișier a fost selectat, salvați calea către fișierul imagine
            self.image_filename = image_filename
            self.send_message(log_filename)

    def handle_create_key(self, log_filename):
        reply = self.sender()
        response_data = json.loads(reply.readAll().data().decode('utf-8'))
        message = response_data.get('message', '')

        if message == "Key stored successfully!":

            # Obtine numele de utilizator si ora curenta
            sender = user.username
            hour = datetime.datetime.now().strftime("%H:%M")
            day = datetime.datetime.now().strftime("%d.%m.%Y") 

            # Creaza un element de mesaj in formatul XML specificat
            root = ET.Element('conversation')
            conversation_string = ET.tostring(root, encoding='utf-8')

            # Cripteaza si salveaza mesajul in fisier
            key = self.get_key()
            cipher_suite = Fernet(key)
            encrypted_message = cipher_suite.encrypt(conversation_string)
            write_to_file(f'logs/{log_filename}', encrypted_message)
        else:
            QMessageBox.critical(self, "Error", message)

    def get_key(self):
        network_manager = QNetworkAccessManager(self)
        url = QUrl("http://localhost:5000/get_key")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
        data = {"username1": user.username, "username2": user.conversation_partner}
        reply = network_manager.post(request, QByteArray(json.dumps(data).encode('utf-8')))
        reply.finished.connect(self.handle_get_key)

        self.loop = QEventLoop()
        reply.finished.connect(self.handle_get_key)
        self.loop.exec_()  # start the event loop
        return self.key

    def handle_get_key(self):
        reply = self.sender()
        response_str = reply.readAll().data().decode('utf-8')

        if response_str.strip():  # check if the response is not empty
            try:
                response_data = json.loads(response_str)
            except json.JSONDecodeError:
                print("Invalid JSON received:", response_str)
                return

            if 'key' in response_data:
                self.key = response_data.get('key', '')
                self.loop.quit()  # quit the event loop
            else:
                message = response_data['message']
                QMessageBox.critical(self, "Error", message)

    def load_messages_from_xml(self, filename):
        self.message_display.clear()

        encrypted_conversation = read_from_file(filename)

        if not encrypted_conversation:
            self.message_display.addItem("There is no conversation so far.")
            return

        key = self.get_key()
        conversation_string = self.decrypt_conversation(encrypted_conversation, key)
        root = ET.fromstring(conversation_string)

        for i, message in enumerate(root.findall('message')):
            content = message.find('content').text
            sender = message.find('sender').text  # Obțineți numele expeditorului
            if content.startswith("iVBORw0KG") or content.startswith("/9j/"):
                try:
                    decoded_image = base64.b64decode(content)
                    pixmap = QPixmap()
                    pixmap.loadFromData(decoded_image)
                    image_label = QLabel()  # QLabel pentru imagine

                    # Setează dimensiunea maximă a imaginii în pixeli
                    max_width = 500  # Lățimea maximă în pixeli
                    max_height = 300  # Înălțimea maximă în pixeli
                    max_size = QSize(max_width, max_height)

                    # Redimensionează imaginea la dimensiunea maximă specificată
                    pixmap = pixmap.scaled(max_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)

                    image_label.setPixmap(pixmap)
                    image_label.setScaledContents(True)  # Permit redimensionarea imaginii

                    # Creați un nou QLabel pentru numele expeditorului
                    sender_label = QLabel(f"{sender}'s image:")
                    if sender == user.username:
                        sender_label.setAlignment(Qt.AlignRight)
                    else:
                        sender_label.setAlignment(Qt.AlignLeft)


                    # Creați un QVBoxLayout și adăugați ambele QLabel-uri
                    layout = QVBoxLayout()
                    layout.addWidget(sender_label)
                    layout.addWidget(image_label)

                    # Creați un QWidget pentru a conține QVBoxLayout
                    widget = QWidget()
                    widget.setLayout(layout)

                    # Setează dimensiunea elementului la dimensiunea widget-ului
                    item = QListWidgetItem(self.message_display)
                    item.setSizeHint(widget.sizeHint())

                    # Adăugați widget-ul la QListWidgetItem
                    self.message_display.setItemWidget(item, widget)
                except binascii.Error:
                    self.display_message(message)
            else:
                self.display_message(message)

        self.message_display.scrollToBottom()

    def decrypt_conversation(self, encrypted_conversation, key):
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_conversation).decode('utf-8')

    def display_message(self, message):
        sender = message.find('sender').text
        day = message.find('day').text
        hour = message.find('hour').text
        content = message.find('content').text

        if self.last_sent_date and day > self.last_sent_date:
            date_label = QLabel(day)
            date_label.setAlignment(Qt.AlignCenter)
            date_item = QListWidgetItem(self.message_display)
            self.message_display.setItemWidget(date_item, date_label)

        if sender and day and hour and content:
            if content.startswith("iVBORw0KG") or content.startswith("/9j/"):
                try:
                    decoded_image = base64.b64decode(content)
                    pixmap = QPixmap()
                    pixmap.loadFromData(decoded_image)
                    image_label = QLabel()  # QLabel pentru imagine

                    # Setează dimensiunea maximă a imaginii în pixeli
                    max_width = 500  # Lățimea maximă în pixeli
                    max_height = 300  # Înălțimea maximă în pixeli
                    max_size = QSize(max_width, max_height)

                    # Redimensionează imaginea la dimensiunea maximă specificată
                    pixmap = pixmap.scaled(max_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)

                    image_label.setPixmap(pixmap)
                    image_label.setScaledContents(True)  # Permit redimensionarea imaginii

                    # Creați un nou QLabel pentru numele expeditorului
                    sender_label = QLabel(f"{sender}'s image:")
                    if sender == user.username:
                        sender_label.setAlignment(Qt.AlignRight)
                    else:
                        sender_label.setAlignment(Qt.AlignLeft)


                    # Creați un QVBoxLayout și adăugați ambele QLabel-uri
                    layout = QVBoxLayout()
                    layout.addWidget(sender_label)
                    layout.addWidget(image_label)

                    # Creați un QWidget pentru a conține QVBoxLayout
                    widget = QWidget()
                    widget.setLayout(layout)

                    # Setează dimensiunea elementului la dimensiunea widget-ului
                    item = QListWidgetItem(self.message_display)
                    item.setSizeHint(widget.sizeHint())

                    # Adăugați widget-ul la QListWidgetItem
                    self.message_display.setItemWidget(item, widget)
                except binascii.Error:
                    self.add_message_to_display(sender, day, hour, content)
            else:
                self.add_message_to_display(sender, day, hour, content)

        self.last_sent_date = message.find('day').text

    def display_new_message(self, filename):
        encrypted_conversation = read_from_file(filename)

        if not encrypted_conversation:
            return

        key = self.get_key()
        conversation_string = self.decrypt_conversation(encrypted_conversation, key)
        root = ET.fromstring(conversation_string)

        last_message = root.findall('message')
        if last_message:  # Verifica daca exista un ultim mesaj
            last_message = last_message[-1]
            self.display_message(last_message)

    def add_message_to_display(self, sender, day, hour, content):
        if sender == user.username:
            message_str = f'{content} : {hour}'
        else:
            message_str = f'{hour} : {content}'

        # Creați un nou QListWidgetItem cu mesajul
        item = QListWidgetItem(message_str)

        # Alegeți alinierea în funcție de expeditor
        if sender == user.username:
            item.setTextAlignment(Qt.AlignRight)
        else:
            item.setTextAlignment(Qt.AlignLeft)

        # Adăugați elementul la QListWidget
        self.message_display.addItem(item)

        self.message_display.scrollToBottom()

    def send_message(self, log_filename):
        # Obtine mesajul din widget-ul de introducere a mesajelor
        message_content = self.message_entry.text()

        # Obtine numele de utilizator si ora curenta
        sender = user.username
        hour = datetime.datetime.now().strftime("%H:%M")
        day = datetime.datetime.now().strftime("%d.%m.%Y") 

        # Citirea conversatiei criptate din fisierul log
        encrypted_conversation = read_from_file(log_filename)

        # obtine cheia de decriptare din db
        key = self.get_key()

        # Decriptarea conversatiei
        cipher_suite = Fernet(key)
        conversation_string = cipher_suite.decrypt(encrypted_conversation).decode('utf-8')

        # Incarca XML-ul existent din string-ul decriptat
        root = ET.fromstring(conversation_string)

        # Creaza un nou element de mesaj si il adauga la XML-ul existent
        message_element = ET.SubElement(root, 'message')
        sender_element = ET.SubElement(message_element, 'sender')
        sender_element.text = sender
        day_element = ET.SubElement(message_element, 'day')
        day_element.text = day
        hour_element = ET.SubElement(message_element, 'hour')
        hour_element.text = hour
        content_element = ET.SubElement(message_element, 'content')
        # content_element.text = message_content

        # Dacă există o imagine încărcată, convertiți-o în Base64 și adăugați-o la mesaj
        if hasattr(self, 'image_filename'):
            with open(self.image_filename, 'rb') as image_file:
                encoded_image = base64.b64encode(image_file.read()).decode('utf-8')
            content_element.text = encoded_image
        else:
            content_element.text = message_content

        # Converteste XML-ul actualizat in string
        conversation_string = ET.tostring(root, encoding='utf-8')

        # Cripteaza si salveaza mesajul in fisier
        encrypted_message = cipher_suite.encrypt(conversation_string)
        write_to_file(log_filename, encrypted_message)

        # Sterge mesajul din widget-ul de introducere a mesajelor
        self.message_entry.clear()
        if hasattr(self, 'image_filename'):
            del self.image_filename

    def back(self):
        self.timer.stop()
        self.showHomeWindow.emit()

        self.hide()

    def delete_conversation(self, filename):
        print("Sterge conversatia")

        # Crearea unui șir XML gol cu doar elementul rădăcină
        empty_conversation_string = "<conversation></conversation>"

        # Obținerea cheii de criptare din baza de date
        key = self.get_key()

        # Criptarea șirului gol
        cipher_suite = Fernet(key)
        encrypted_empty_conversation = cipher_suite.encrypt(empty_conversation_string.encode('utf-8'))

        # Scrierea șirului gol criptat înapoi în fișier
        write_to_file(filename, encrypted_empty_conversation)

        # Golirea afișajului de mesaje
        self.message_display.clear()

        print("Conversatia a fost stearsa")

    class MyClass:
        def __init__(self, log_filename, window):
            self.log_filename = log_filename
            self.window = window
            self.last_modified = os.path.getmtime(log_filename)

        def verify_is_modified(self):
            current_modified = os.path.getmtime(self.log_filename)
            if current_modified != self.last_modified:
                self.window.display_new_message(self.log_filename)

                self.last_modified = current_modified

def write_to_file(filename, data):
    # Obținerea semaforului
    with sem:
        try:
            # Scrierea datelor în fișier
            with open(filename, 'wb') as f:
                f.write(data)
        except IOError as e:
            print(f"A apărut o eroare la scrierea în fișierul {filename}: {e}")
        except Exception as e:
            print(f"A apărut o eroare neașteptată: {e}")

def read_from_file(filename):
    # Verificarea dacă fișierul există înainte de a încerca să îl citim
    if not os.path.exists(filename):
        print(f"Fișierul {filename} nu există.")
        return None

    # Obținerea semaforului
    with sem:
        try:
            # Citirea datelor din fișier
            with open(filename, 'rb') as f:
                data = f.read()
        except IOError as e:
            print(f"A apărut o eroare la citirea fișierului {filename}: {e}")
            return None

    return data

class ClickableLabel(QLabel):
    clicked = pyqtSignal()

    def __init__(self, text=None):
        super().__init__(text)

    def mousePressEvent(self, event):
        self.clicked.emit()

def start_application():
    app = QApplication([])
    registration_window = RegistrationWindow()
    conversation_window = ConversationWindow()
    home_window = HomeWindow(conversation_window)
    login_window = LoginWindow(home_window)

    # Conectați semnalul din fereastra de autentificare la slotul pentru afișarea fereastra de înregistrare
    login_window.showRegistrationWindow.connect(registration_window.show)
    login_window.showHomeWindow.connect(home_window.show)
    registration_window.showLoginWindow.connect(login_window.show)
    home_window.showConversationWindow.connect(conversation_window.show)
    home_window.showLoginWindow.connect(login_window.show)
    conversation_window.showHomeWindow.connect(home_window.show)

    login_window.show()
    app.exec_()