import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QListWidget, QMessageBox
from PyQt5.QtCore import Qt
import socket
import threading

class UDPListener:
    def __init__(self):
        # Get the IP address of the machine
        self.ip_address = socket.gethostbyname(socket.gethostname())
        self.ip_listen_address = None
        self.port = None
        self.running = False

    def start(self):
        if not self.ip_listen_address or not self.port:
            return

        self.running = True

        # Create a UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Bind the socket to the port and IP address
            self.sock.bind((self.ip_listen_address, self.port))
            print(f"Listening for UDP packets on {self.ip_listen_address}:{self.port}...")

            # Listen for incoming UDP packets
            while self.running:
                data, addr = self.sock.recvfrom(1024)
                print(f"Received UDP data from {addr[0]}:{addr[1]}: {data.decode()}")
        except socket.error as e:
            print(f"Error occurred while listening for UDP packets: {str(e)}")

        self.sock.close()

    def stop(self):
        self.running = False

class UDPStreamer:
    def __init__(self, parent):
        self.parent = parent
        self.ip_addresses = []
        self.ports = []

    def add_address_port(self, ip_address, port):
        self.ip_addresses.append(ip_address)
        self.ports.append(port)

    def remove_address_port(self, index):
        if 0 <= index < len(self.ip_addresses):
            self.ip_addresses.pop(index)
            self.ports.pop(index)

    def restream_packets(self):
        listener = UDPListener()

        for ip_address, port in zip(self.ip_addresses, self.ports):
            listener.ip_listen_address = ip_address
            listener.port = port
            thread = threading.Thread(target=listener.start)
            thread.start()

        thread.join()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UDP Restreamer")
        self.setGeometry(200, 200, 400, 400)

        self.streamer = UDPStreamer(self)

        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout(central_widget)

        address_layout = QHBoxLayout()
        self.ip_address_input = QLineEdit()
        self.ip_address_input.setPlaceholderText("IP Address")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port")
        add_button = QPushButton("Add")
        add_button.clicked.connect(self.add_address_port)
        address_layout.addWidget(self.ip_address_input)
        address_layout.addWidget(self.port_input)
        address_layout.addWidget(add_button)

        self.address_list = QListWidget()
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(self.remove_address_port)

        layout.addLayout(address_layout)
        layout.addWidget(QLabel("IP Addresses and Ports"))
        layout.addWidget(self.address_list)
        layout.addWidget(remove_button)

        restream_button = QPushButton("Start Restreaming")
        restream_button.clicked.connect(self.start_restreaming)
        layout.addWidget(restream_button)

        self.setCentralWidget(central_widget)

    def add_address_port(self):
        ip_address = self.ip_address_input.text()
        port = self.port_input.text()

        if ip_address and port:
            self.streamer.add_address_port(ip_address, int(port))
            self.address_list.addItem(f"{ip_address}:{port}")

            self.ip_address_input.clear()
            self.port_input.clear()
        else:
            QMessageBox.warning(self, "Error", "Please enter IP address and port.")

    def remove_address_port(self):
        selected_row = self.address_list.currentRow()
        if selected_row >= 0:
            self.streamer.remove_address_port(selected_row)
            self.address_list.takeItem(selected_row)

    def start_restreaming(self):
        self.streamer.restream_packets()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
