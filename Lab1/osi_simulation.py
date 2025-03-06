import socket
import sys

class PhysicalLayer:
    def __init__(self, ip, port, mode='server'):
        self.ip = ip
        self.port = port
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if mode == 'server':
            self.sock.bind((ip, port))
            self.sock.listen(1)
            print(f"[PhysicalLayer] Server listening on {ip}:{port}")
            self.conn, addr = self.sock.accept()
            print(f"[PhysicalLayer] Connection accepted from {addr}")
        else:
            self.sock.connect((ip, port))
            self.conn = self.sock
            print(f"[PhysicalLayer] Connected to server {ip}:{port}")

    def send(self, bitstream: str):
        # Convert bitstream (a string of 0s and 1s) to bytes.
        byte_length = (len(bitstream) + 7) // 8
        int_val = int(bitstream, 2)
        byte_data = int_val.to_bytes(byte_length, byteorder='big')
        self.conn.sendall(byte_data)
        print(f"[PhysicalLayer] Sent bitstream: {bitstream}")

    def receive(self) -> str:
        data = self.conn.recv(4096)
        if not data:
            return ''
        int_val = int.from_bytes(data, byteorder='big')
        # Format bitstream with leading zeros (8 bits per byte).
        bitstream = format(int_val, '0{}b'.format(len(data) * 8))
        print(f"[PhysicalLayer] Received bitstream: {bitstream}")
        return bitstream

class DataLinkLayer:
    def __init__(self, physical_layer: PhysicalLayer, mac_address: str):
        self.physical_layer = physical_layer
        self.mac_address = mac_address

    def send(self, payload: str):
        # Attach a MAC header to form the frame.
        frame = f"DL[{self.mac_address}]|{payload}"
        # Convert the frame to a bitstream (8-bit binary for each character).
        bitstream = ''.join(format(ord(c), '08b') for c in frame)
        print(f"[DataLinkLayer] Sending frame: {frame}")
        self.physical_layer.send(bitstream)

    def receive(self):
        bitstream = self.physical_layer.receive()
        # Convert bitstream back into a string.
        chars = [chr(int(bitstream[i:i+8], 2)) for i in range(0, len(bitstream), 8)]
        frame = ''.join(chars)
        print(f"[DataLinkLayer] Received frame: {frame}")
        try:
            header, payload = frame.split('|', 1)
        except ValueError:
            header, payload = None, frame
        return header, payload

class NetworkLayer:
    def __init__(self, data_link_layer: DataLinkLayer, ip_address: str):
        self.data_link_layer = data_link_layer
        self.ip_address = ip_address

    def send(self, payload: str):
        packet = f"NW[{self.ip_address}]|{payload}"
        print(f"[NetworkLayer] Sending packet: {packet}")
        self.data_link_layer.send(packet)

    def receive(self):
        header, packet = self.data_link_layer.receive()
        try:
            net_header, payload = packet.split('|', 1)
        except ValueError:
            net_header, payload = None, packet
        print(f"[NetworkLayer] Received packet with header: {net_header}")
        return net_header, payload

class TransportLayer:
    def __init__(self, network_layer: NetworkLayer, sequence_number: int = 1):
        self.network_layer = network_layer
        self.sequence_number = sequence_number

    def send(self, payload: str):
        segment = f"TP[{self.sequence_number}]|{payload}"
        print(f"[TransportLayer] Sending segment: {segment}")
        self.network_layer.send(segment)
        self.sequence_number += 1

    def receive(self):
        net_header, segment = self.network_layer.receive()
        try:
            tp_header, payload = segment.split('|', 1)
        except ValueError:
            tp_header, payload = None, segment
        print(f"[TransportLayer] Received segment with header: {tp_header}")
        return tp_header, payload

class SessionLayer:
    def __init__(self, transport_layer: TransportLayer, session_id: str = "SESSION1"):
        self.transport_layer = transport_layer
        self.session_id = session_id

    def send(self, payload: str):
        session_packet = f"SS[{self.session_id}]|{payload}"
        print(f"[SessionLayer] Sending session packet: {session_packet}")
        self.transport_layer.send(session_packet)

    def receive(self):
        tp_header, session_packet = self.transport_layer.receive()
        try:
            ss_header, payload = session_packet.split('|', 1)
        except ValueError:
            ss_header, payload = None, session_packet
        print(f"[SessionLayer] Received session packet with header: {ss_header}")
        return ss_header, payload

class PresentationLayer:
    def __init__(self, session_layer: SessionLayer):
        self.session_layer = session_layer

    def send(self, payload: str):
        # Simulate encryption/encoding by reversing the string.
        encoded = payload[::-1]
        presentation_packet = f"PR:{encoded}"
        print(f"[PresentationLayer] Sending presentation packet: {presentation_packet}")
        self.session_layer.send(presentation_packet)

    def receive(self):
        ss_header, presentation_packet = self.session_layer.receive()
        print(f"[PresentationLayer] Received presentation packet: {presentation_packet}")
        if presentation_packet.startswith("PR:"):
            encoded = presentation_packet[3:]
            # Decode by reversing the string.
            decoded = encoded[::-1]
            return decoded
        else:
            return presentation_packet

class ApplicationLayer:
    def __init__(self, presentation_layer: PresentationLayer):
        self.presentation_layer = presentation_layer

    def send(self, message: str):
        app_message = f"AP:{message}"
        print(f"[ApplicationLayer] Sending application message: {app_message}")
        self.presentation_layer.send(app_message)

    def receive(self):
        data = self.presentation_layer.receive()
        print(f"[ApplicationLayer] Raw received data: {data}")
        if data.startswith("AP:"):
            return data[3:]
        return data

class FileTransferApplicationLayer(ApplicationLayer):
    def send_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                print(f"[FileTransfer] Starting file transfer: {filepath}")
                while True:
                    # Read the file in chunks (adjust the chunk size if needed)
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    # Mark each chunk so the receiver knows it is part of a file
                    message = "FILECHUNK:" + chunk
                    self.send(message)
            # Signal end-of-file.
            self.send("FILEEOF")
            print("[FileTransfer] File transfer complete.")
        except Exception as e:
            print("[FileTransfer] Error reading file:", e)

    def receive_file(self, output_filepath: str):
        try:
            with open(output_filepath, 'w') as f:
                print(f"[FileTransfer] Receiving file and saving to: {output_filepath}")
                while True:
                    message = self.receive()
                    # If the end-of-file marker is received, stop.
                    if message == "FILEEOF":
                        print("[FileTransfer] End-of-file marker received.")
                        break
                    if message.startswith("FILECHUNK:"):
                        chunk = message[len("FILECHUNK:"):]
                        f.write(chunk)
            print("[FileTransfer] File received successfully.")
        except Exception as e:
            print("[FileTransfer] Error writing file:", e)

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage: python file_transfer_osi.py [server|client]")
        sys.exit(1)
    mode = sys.argv[1]
    ip = '127.0.0.1'
    port = 5000

    # Build the OSI stack.
    if mode == 'server':
        phys = PhysicalLayer(ip, port, mode='server')
        data_link = DataLinkLayer(phys, "AA:BB:CC:DD:EE:FF")
        network = NetworkLayer(data_link, "192.168.1.1")
        transport = TransportLayer(network)
        session = SessionLayer(transport, session_id="SESSION_SERVER")
        presentation = PresentationLayer(session)
        app = FileTransferApplicationLayer(presentation)
        
        app.receive_file("received_file.txt")
    else:
        phys = PhysicalLayer(ip, port, mode='client')
        data_link = DataLinkLayer(phys, "11:22:33:44:55:66")
        network = NetworkLayer(data_link, "192.168.1.2")
        transport = TransportLayer(network)
        session = SessionLayer(transport, session_id="SESSION_CLIENT")
        presentation = PresentationLayer(session)
        app = FileTransferApplicationLayer(presentation)
        
        app.send_file("send_file.txt")

if __name__ == '__main__':
    main()
