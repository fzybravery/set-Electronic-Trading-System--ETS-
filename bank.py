import RSA_sign as rsasign
import binascii
from socket import *
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import DES_ED as des
import CapToken as CapTok_gen
import time


class Bank:
    def __init__(self):
        # 设置本机作为服务器的IP地址和端口
        self.address = '127.0.0.1'
        self.port = 36669

        # 公钥密码
        self.sk_B,self.pk_B = rsasign.generate_keypair()
        # 十六进制字符串形式的公私钥
        self.sk_B_hex = binascii.hexlify(self.sk_B).decode()
        self.pk_B_hex = binascii.hexlify(self.pk_B).decode()
        
        # ID信息(随机数)
        self.ID_B = 'bank'

        # DES密钥
        self.sk_1 = -1#保存持卡人的DES密钥
        self.sk_2 = -1#保存支付网关的DES密钥
        self.sk_3 = -1#保存支付网关的DES密钥
        self.sk_4 = binascii.hexlify(get_random_bytes(8)).decode()#保存商家的DES密钥

        # 证书
        self.Cert_C = []#初始化为0
        self.Cert_M = []#商家的证书
        self.Cert_P = []#支付网关的证书
        self.Cert_B = []#持卡人发行行的证书

        # 持卡人账户信息
        self.acc = ""

        # CapTok安全令牌(使用DES的密钥)
        self.CapTok = CapTok_gen.generate_cap_token(self.sk_4)#生成安全令牌

    def connect_to_CA(self):
    #连接CA服务器获取证书
        server_HOST = '127.0.0.1'
        server_PORT = 10086
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((server_HOST,server_PORT))
        self.get_cert(s)#获取证书
        s.close()#关闭与CA的连接

    def connect_to_payment(self):
        # 作为服务器方与支付网关建立连接
        server_socket = socket(AF_INET,SOCK_STREAM)
        server_socket.bind((bank.address,bank.port))
        server_socket.listen(1)
        # 循环等待连接支付网关
        print("*********正在与CA服务器进行连接*********\n")
        while True:
            try:
                conn, addr = server_socket.accept()
                print("---支付网关连接成功！---\n")
                break
            except Exception as e:
                print(f"---商家连接失败，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试
        print("##########连接建立成功开始进行支付##########\n")
        time.sleep(1)
        self.send_messege_list(conn,self.Cert_B)
        print("---等待支付网关的支付授权请求中....---\n")
        time.sleep(1)

        if self.check_AuthREQ(conn):#验证支付授权请求
            print("支付授权请求验证成功！")
            print("---发送支付授权请求中....---\n")
            self.AuthRES(conn)#发送支付授权响应
            # 等待支付网关的请款请求
            print("---等待支付网关的请款请求中....---\n")
            time.sleep(1)
            if self.check_CapREQ(conn):
                print("请款请求验证成功！")
                self.CapRES(conn)#发送请款响应
                print("====================交易成功====================")

        else:
            print("支付授权请求验证失败！")
            conn.close()#关闭与支付网关的连接
            server_socket.close()#关闭服务器的连接
            

    def send_messege_list(self,s,message):#发送消息，即支付请求订单信息
        #传入的参数是列表
        data = ""
        for i in range(len(message)):
            data += message[i]
            if i!= len(message)-1:
                data += "||"
        #print("发送消息：",data)
        s.sendall(data.encode())
    
    def send_messege(self,s,message):#发送消息
        #传入的参数是字符串
        s.sendall(message.encode())

    def receive_messege_list(self,s):#接收消息，即支付响应信息
        data = s.recv(2048).decode()
        #将接受到的信息按"||"分割成列表
        return data.split("||")
        
    def receive_messege(self,s):#接收消息
        data = s.recv(2048).decode()
        # 接受到的信息直接返回
        return data

    def check_cert(self,Cert):#验证证书的有效性
        message = Cert[0]+Cert[1]#获取被验证方的ID和公钥
        if rsasign.verify_signature(self.pk_CA,message,binascii.unhexlify(Cert[2])):
            return True
        else:
            return False

    def get_cert(self,s):#获取证书
        #为了方便拆分，将需要拼接的信息放到一个列表中
        message = [self.ID_B,self.pk_B_hex]#ID||pk
        self.send_messege_list(s,message)#发送信息给CA
        receive_info = self.receive_messege_list(s)#接收CA的回复信息
        self.Cert_B = receive_info[0:3:]#接受CA发送过来的证书
        self.pk_CA = binascii.unhexlify(receive_info[3])#接受CA发送过来的CA的公钥
        if self.check_cert(self.Cert_B):#验证证书的有效性
            print("证书有效")
            print("持卡人发行行证书：",self.Cert_B)
            self.send_messege(s,"True")#发送支付请求成功信息
        else:
            print("证书无效")
            self.send_messege(s,"False")#发送支付请求失败信息

    def check_AuthREQ(self,s):#验证支付授权请求
        #接收支付网关发送的支付请求信息
        receive_info = self.receive_messege_list(s)
        print("---支付网关支付授权信息接受成功,正在验证---\n")
        time.sleep(1)
        self.Cert_P = receive_info[2::]#支付网关的证书
        if self.check_cert(self.Cert_P):#验证支付网关的证书有效性
            print("支付网关证书有效")
            enc_acc = receive_info[0]#接收到的加密账户信息
            acc_sk3 = rsasign.decrypt_message(self.sk_B,binascii.unhexlify(enc_acc))#解密账户信息
            self.sk_3 = acc_sk3[0:16:]#保存支付网关的DES密钥
            self.acc = acc_sk3[16::]#保存持卡人的账户信息
            # 验证支付网关的支付授权请求
            enc_sign_AuthREQ = receive_info[1]#接收到的加密的支付授权请求的签名信息
            sign_AuthREQ = des.des_decrypt(binascii.unhexlify(self.sk_3),binascii.unhexlify(enc_sign_AuthREQ))
            signature_AuthREQ , AuthREQ = sign_AuthREQ.split("**")
            H_AuthREQ = (SHA256.new(AuthREQ.encode('utf-8'))).hexdigest()#对支付授权信息进行哈希
            pk_P = binascii.unhexlify(self.Cert_P[1])#支付网关的公钥
            if rsasign.verify_signature(pk_P,H_AuthREQ,binascii.unhexlify(signature_AuthREQ)):
                print("支付授权请求验证成功！")
                self.send_messege(s,"True")#发送支付授权响应成功信息
                return True
            else:
                print("支付授权请求验证失败！")
                return False
        else:
            print("支付网关证书无效,支付授权请求验证失败")
            return False
        
    def AuthRES(self,s):
        # 发送支付授权响应
        # 向持卡人发行行请求支付授权
        send_list = []#发送信息的列表
        pk_P = binascii.unhexlify(self.Cert_P[1])#获取持卡人发行行的公钥
        enc_acc = rsasign.encrypt_message(pk_P,(self.sk_4+self.acc))#对账户信息进行加密（利用发行行的公钥）
        send_list.append(binascii.hexlify(enc_acc).decode())#添加加密后的账户信息(十六进制字符串形式)
        # 发送商家的证书、持卡人证书、支付请求信息
        Auth_RES = "The payment authorization request has been approved."
        H_Auth_res = (SHA256.new(Auth_RES.encode('utf-8'))).hexdigest()#对支付授权信息进行哈希
        signature_Auth_res = binascii.hexlify(rsasign.sign_message(self.sk_B,H_Auth_res)).decode()#对支付授权信息进行签名
        des_enc_sar = des.des_encrypt(binascii.unhexlify(self.sk_4),(signature_Auth_res+"**"+Auth_RES))#利用支付网关的密钥对签名进行加密
        send_list.append(binascii.hexlify(des_enc_sar).decode())#添加加密后的签名(十六进制字符串形式)
        # 对安全支付令牌进行哈希
        H_CapTok = (SHA256.new(self.CapTok.encode('utf-8'))).hexdigest()
        signature_Captok = binascii.hexlify(rsasign.sign_message(self.sk_B,H_CapTok)).decode()#对安全支付令牌进行签名
        des_enc_info = des.des_encrypt(binascii.unhexlify(self.sk_4),(signature_Captok+"**"+self.CapTok))
        send_list.append(binascii.hexlify(des_enc_info).decode())#添加加密后的安全支付令牌(十六进制字符串形式)

        # 持卡人发行行的证书
        send_list += self.Cert_B#添加支付网关的证书
        self.send_messege_list(s,send_list)#发送信息给持卡人发行行
        # 接收持卡人发行行的回复信息
        rec_message = self.receive_messege(s)
        if rec_message == "True":
            print("支付授权发送成功")
        else:
            print("支付授权发送失败")

    def check_CapREQ(self,s):
        # 接收请款请求
        receive_info = self.receive_messege_list(s)
        print("---支付网关请款信息接受成功,正在验证---\n")
        time.sleep(1)
        self.Cert_P = receive_info[1::]#支付网关的证书
        if self.check_cert(self.Cert_P):#验证支付网关的证书有效性
            print("支付网关证书有效")
            enc_sign_CapREQ = receive_info[0]#接收到的加密的请款请求的签名信息
            sign_CapREQ = des.des_decrypt(binascii.unhexlify(self.sk_4),binascii.unhexlify(enc_sign_CapREQ))
            signature_CapREQ , CapREQ = sign_CapREQ.split("**")
            H_CapREQ = (SHA256.new(CapREQ.encode('utf-8'))).hexdigest()#对请款信息进行哈希
            pk_P = binascii.unhexlify(self.Cert_P[1])#支付网关的公钥
            if rsasign.verify_signature(pk_P,H_CapREQ,binascii.unhexlify(signature_CapREQ)):
                print("请款请求验证成功！")
                self.send_messege(s,"True")#发送请款响应成功信息
                return True
            else:
                print("请款请求验证失败！")
                return False
        else:
            print("支付网关证书无效,请款请求验证失败")
            return False
        

    def CapRES(self,s):
        # 发送请款响应
        # 向商家请求请款
        CapRES = "The payment has been made."
        send_list = []#发送信息的列表
        H_CapRES = (SHA256.new(CapRES.encode('utf-8'))).hexdigest()#对请款信息进行哈希
        signature_CapRES = binascii.hexlify(rsasign.sign_message(self.sk_B,H_CapRES)).decode()#对请款信息进行签名
        des_enc_CapRES = des.des_encrypt(binascii.unhexlify(self.sk_4),(signature_CapRES+"**"+CapRES))#利用支付网关的密钥对签名进行加密
        send_list.append(binascii.hexlify(des_enc_CapRES).decode())#添加加密后的签名(十六进制字符串形式)
        send_list+=self.Cert_B#添加发行行的证书
        self.send_messege_list(s,send_list)#发送信息给商家
        # 接收商家的回复信息
        rec_message = self.receive_messege(s)
        if rec_message == "True":
            print("请款发送成功")
        else:
            print("请款发送失败")

if __name__ == '__main__':
    bank = Bank()
    print("====================连接CA服务器获取证书====================")
    bank.connect_to_CA()
    print("====================连接支付网关====================")
    bank.connect_to_payment()