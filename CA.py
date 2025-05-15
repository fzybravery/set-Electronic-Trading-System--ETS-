import threading
import RSA_sign as rsasign
import binascii
from socket import *


class CA:
    def __init__(self):
        self.sk_CA, self.pk_CA = rsasign.generate_keypair()
        self.sk_CA_hex = binascii.hexlify(self.sk_CA).decode()
        self.pk_CA_hex = binascii.hexlify(self.pk_CA).decode()

    def connection(self):
        # CA服务器地址和端口
        self.HOST = '127.0.0.1'
        self.PORT = 10086

        # 创建 TCP 套接字
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        # 绑定地址和端口
        self.server_socket.bind((self.HOST, self.PORT))
        # 开始监听
        self.server_socket.listen(5)
        print(f"Server listening on {self.HOST}:{self.PORT}...")
        print("====================CA服务器开启,等待客户端连接===================")

        # 处理客户端连接
        while True:
            # 等待客户端连接
            client_socket, client_address = self.server_socket.accept()
            print(f"Connected to client {client_address}")

            # 创建线程处理客户端请求
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def send_message_list(self, client_socket, message):
        # 传入的参数是列表
        data = "||".join(message)
        client_socket.sendall(data.encode())

    def send_message(self, client_socket, message):
        # 传入的参数是字符串
        client_socket.sendall(message.encode())

    def receive_message_list(self, client_socket):
        data = client_socket.recv(1024).decode()
        # 将接收到的信息拆分为列表
        return data.split("||")

    def receive_message(self, client_socket):
        data = client_socket.recv(1024).decode()
        return data

    def handle_client(self, client_socket):
        try:
            print("**********证书分发进程**********")
            # 接收客户端请求
            receive_info = self.receive_message_list(client_socket)
            message = receive_info[0] + receive_info[1]

            # 对消息进行签名
            signature = rsasign.sign_message(self.sk_CA, message)
            signature_hex = binascii.hexlify(signature).decode()
            receive_info.append(signature_hex)
            receive_info.append(self.pk_CA_hex)

            # 发送证书给客户端
            self.send_message_list(client_socket, receive_info)
            print(f"{receive_info[0]}'s certificate sent to client {client_socket.getpeername()}.")
            
            # 等待接受客户端的反馈
            print(f"{receive_info[0]}'s certificate is ",self.receive_message(client_socket))
            # 关闭客户端连接
            client_socket.close()

        except Exception as e:
            print(f"Error handling client: {e}")

if __name__ == '__main__':
    ca = CA()
    ca.connection()
