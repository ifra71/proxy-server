#DECENT ONE 
import sys
import logging
import os
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QTextEdit,
    QPushButton, QWidget, QLineEdit, QLabel, QListWidget, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import QThread, Qt
from PyQt5.QtGui import QPalette, QColor, QFont
from urllib import request, error
import socketserver
from datetime import datetime

# Blocked URLs List
BLOCKED = ["example.com", "blockedsite.com"]

# Logger Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Proxy Handler
class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        url = self.request.recv(1024).decode().strip()
        if any(blocked in url for blocked in BLOCKED):
            self.request.sendall(b"Access Denied: Blocked URL")
            if hasattr(self.server, 'gui'):  # Ensure GUI is available
                self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Access Denied: {url}")
            return

        # Cache Key
        cache_key = hashlib.md5(url.encode()).hexdigest()
        cache_file = os.path.join("proxy_cache", cache_key)

        if os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                logging.info(f"Serving from cache: {url}")
                self.request.sendall(f.read())
                if hasattr(self.server, 'gui'):  # Ensure GUI is available
                    self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Served from cache: {url}")
                return

        try:
            req = request.Request(url)
            with request.urlopen(req) as response:
                content = response.read()
                with open(cache_file, "wb") as f:
                    f.write(content)
                self.request.sendall(content)
                if hasattr(self.server, 'gui'):  # Ensure GUI is available
                    self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Fetched and cached: {url}")
        except error.URLError as e:
            logging.error(f"Error fetching {url}: {e}")
            self.request.sendall(b"Internal Proxy Error")
            if hasattr(self.server, 'gui'):  # Ensure GUI is available
                self.server.gui.log_message(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error fetching {url}: {e}")

# Proxy Server
class ProxyServer:
    def __init__(self, port=8080, gui=None):
        self.port = port
        self.httpd = None
        self.gui = gui

    def run(self):
        with socketserver.TCPServer(("", self.port), ProxyHandler) as httpd:
            # Pass the GUI instance to the handler
            httpd.RequestHandlerClass.gui = self.gui
            self.httpd = httpd
            logging.info(f"Proxy server running on port {self.port}")
            httpd.serve_forever()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            logging.info("Proxy server stopped")

class ProxyThread(QThread):
    def __init__(self, port=8080, gui=None):
        super().__init__()
        self.server = ProxyServer(port, gui)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.stop()

class ProxyGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Proxy Server")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #eeeeee;")

        # Central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()

        # Header
        self.header_label = QLabel("Python Proxy Server")
        self.header_label.setAlignment(Qt.AlignCenter)
        self.header_label.setFont(QFont("Arial", 20, QFont.Bold))
        self.header_label.setStyleSheet("color: #3C5B6F;")
        self.layout.addWidget(self.header_label)

        # Project Description
        self.description_label = QLabel("A Python-based Proxy Server that provides URL blocking.")
        self.description_label.setAlignment(Qt.AlignCenter)
        self.description_label.setFont(QFont("Arial", 12))
        self.layout.addWidget(self.description_label)

        # Logs
        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #ffffff; border: 1px solid #3C5B6F;")
        self.layout.addWidget(self.log_area)

        # Controls
        self.start_button = QPushButton("Start Proxy", self)
        self.start_button.setStyleSheet("background-color: #3C5B6F; color: #ffffff;")
        self.start_button.clicked.connect(self.start_proxy)
        self.layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Proxy", self)
        self.stop_button.setStyleSheet("background-color: #3C5B6F; color: #ffffff;")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_proxy)
        self.layout.addWidget(self.stop_button)

        # Blocked URLs
        self.blocked_urls_label = QLabel("Blocked URLs/IPs:", self)
        self.layout.addWidget(self.blocked_urls_label)
        self.blocked_list = QListWidget(self)
        self.blocked_list.addItems(BLOCKED)
        self.blocked_list.setStyleSheet("background-color: #ffffff; border: 1px solid #3C5B6F;")
        self.layout.addWidget(self.blocked_list)

        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Add a URL/IP to block")
        self.url_input.setStyleSheet("background-color: #ffffff; border: 1px solid #3C5B6F;")
        self.layout.addWidget(self.url_input)

        self.add_url_button = QPushButton("Add URL/IP", self)
        self.add_url_button.setStyleSheet("background-color: #3C5B6F; color: #ffffff;")
        self.add_url_button.clicked.connect(self.add_blocked_url)
        self.layout.addWidget(self.add_url_button)

        # Logs Table
        self.log_table = QTableWidget(self)
        self.log_table.setColumnCount(2)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Request Status"])
        self.log_table.setStyleSheet("background-color: #ffffff; border: 1px solid #3C5B6F;")
        self.layout.addWidget(self.log_table)

        # Footer
        self.footer_label = QLabel("Submitted by: Burhan Ahmed and Ifra Fazal")
        self.footer_label.setAlignment(Qt.AlignCenter)
        self.footer_label.setFont(QFont("Arial", 10))
        self.footer_label.setStyleSheet("color: #3C5B6F;")
        self.layout.addWidget(self.footer_label)

        self.central_widget.setLayout(self.layout)
        self.proxy_thread = None

    def log_message(self, message):
        self.log_area.append(message)
        self.update_logs_table(message)

    def update_logs_table(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        status = message.split(' - ')[-1]
        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)
        self.log_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.log_table.setItem(row_position, 1, QTableWidgetItem(status))

    def start_proxy(self):
        self.proxy_thread = ProxyThread(port=8080, gui=self)
        self.proxy_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_message("Proxy server started on port 8080")

    def stop_proxy(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread.wait()
            self.proxy_thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("Proxy server stopped")

    def add_blocked_url(self):
        url = self.url_input.text().strip()
        if url:
            BLOCKED.append(url)
            self.blocked_list.addItem(url)
            self.log_message(f"Blocked URL/IP added: {url}")
            self.url_input.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = ProxyGUI()
    gui.show()
    sys.exit(app.exec_())
