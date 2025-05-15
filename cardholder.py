import RSA_sign as rsasign
import binascii
from socket import *
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import DES_ED as des
import time


class Cardholder:
    def __init__(self,request_info,OI_info,PI_info,acc_info):

        # 信息(均为十六进制字符串形式)
        self.OI = OI_info#订单信息，包括商品名称、数量、价格
        self.PI = PI_info#支付信息，包括支付方式
        self.req_info = request_info#支付请求信息
        self.acc_info = acc_info#支付账号和密码
        self.ID_C = 'cardholder'# ID信息

        # RSA的公私钥
        self.sk_C,self.pk_C = rsasign.generate_keypair()
        # 十六进制字符串形式的公私钥
        self.sk_C_hex = binascii.hexlify(self.sk_C).decode()
        self.pk_C_hex = binascii.hexlify(self.pk_C).decode()
        # 公私钥的长度，为了方便验证
        self.sk_C_len = len(self.sk_C)
        self.pk_C_len = len(self.pk_C)

        # DES密钥
        self.sk_1 = binascii.hexlify(get_random_bytes(8)).decode()#生成8字节的DES密钥
        #注意，这里初始生成的密钥并不是十六进制字符串，而是字节形式,通过binascii.hexlify()转换为十六进制字符串
        
        # 证书
        self.Cert_C = []#初始化为0
        self.Cert_M = []#商家的证书
        self.Cert_P = []#支付网关的证书

    def connect_to_CA(self):
        #连接CA服务器获取证书
        server_HOST = '127.0.0.1'
        server_PORT = 10086
        
        # 循环等待连接CA服务器
        print("*********正在与CA服务器进行连接*********")
        while True:
            try:
                s = socket(AF_INET,SOCK_STREAM)
                s.connect((server_HOST,server_PORT))
                print("---成功连接CA服务器---")
                break
            except Exception as e:
                print(f"---CA连接失败，重试中... 错误: {e}---")
                time.sleep(1)  # 等待1秒后重试
        self.get_cert(s)#获取证书
        s.close()#关闭与CA的连接


    def connect_to_marketer(self):
        #连接商家服务器获取订单信息
        server_HOST = '127.0.0.1'
        server_PORT = 25625
        
        # 循环等待连接商家服务器
        print("*********正在与商家服务器进行连接*********\n")
        while True:
            try:
                s = socket(AF_INET,SOCK_STREAM)
                s.connect((server_HOST,server_PORT))
                print("---成功连接商家服务器---\n")
                break
            except Exception as e:
                print(f"---商家连接失败，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试

        print("##########连接建立成功开始进行支付##########\n")
        time.sleep(1)
        self.send_messege(s,self.req_info)#发送订单信息
        print("---已发送支付请求，等待商家回复---\n")
        time.sleep(1)
        receive_info = self.receive_messege_list(s)#接收商家回复的签名信息
        print("商家发送的支付请求的签名：",receive_info[0])
        self.Cert_M = receive_info[1:4:]#接收商家的证书
        print("商家证书：",self.Cert_M)
        self.Cert_P = receive_info[4:7:]#接收支付网关的证书
        print("支付网关证书：",self.Cert_P)
        print("---验证商家发送信息的正确性---\n")
        time.sleep(1)
        if self.check_response(receive_info[0]):#验证接收到的信息的正确性
            print("验证商家响应成功（并向商家反馈验证结果）")
            self.send_messege(s,"Verify success")
            print("---发送订单信息和支付信息---\n")
            time.sleep(1)
            self.send_OI_PI(s)#发送订单信息和支付信息
            print("---等待商家的验证订单回应---\n")
            if self.check_response_order(s):#验证商家的发货信息
                self.confirm_receipt(s)#确认收货
        else:
            print("验证商家响应失败（并向商家反馈验证结果）")
            self.send_messege(s,"Verify failed")

        s.close()#关闭与商家的连接

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
        data = s.recv(4096).decode()
        #将接受到的信息按"||"分割成列表
        return data.split("||")
    
    def receive_messege(self,s):#接收消息
        data = s.recv(2048).decode()
        # 接受到的信息直接返回
        return data

    def check_response(self,messege):#验证接收到的消息的正确性
        H_req = SHA256.new(self.req_info.encode('utf-8'))#对获取的购买请求进行哈希函数
        H_req_hex = H_req.hexdigest()#将哈希值转换为十六进制字符串
        pk_M = binascii.unhexlify(self.Cert_M[1])#获取商家的公钥
        if self.check_cert(self.Cert_P) and self.check_cert(self.Cert_M) and rsasign.verify_signature(pk_M,H_req_hex,binascii.unhexlify(messege)):
            return True
        else:
            return False

    def send_OI_PI(self,s):#发送订单信息和支付信息
        # 发送的信息包括两个列表，第一个列表是证书
        # 第二个列表是H_OI_PI的签名，RSA加密OI的结果，H_PI,账户的RSA加密信息，级联签名的DES加密结果
        send_info_list = []#发送信息列表
        #print("支付信息：",self.OI)
        H_OI = (SHA256.new(self.OI.encode('utf-8'))).hexdigest()#对订单信息进行哈希函数
        H_PI = (SHA256.new(self.PI.encode('utf-8'))).hexdigest()#对支付信息进行哈希函数
        print("持卡人证书：",self.Cert_C)
        self.send_messege_list(s,self.Cert_C)#先发送证书给商家
        H_OI_PI = (SHA256.new((H_OI+H_PI).encode('utf-8'))).hexdigest()#对订单信息和支付信息进行哈希函数
        signature_hex = binascii.hexlify(rsasign.sign_message(self.sk_C,H_OI_PI)).decode()#对哈希值进行签名
        send_info_list.append(signature_hex)
        #利用商家公钥对OI进行加密
        pk_M = binascii.unhexlify(self.Cert_M[1])#获取商家的公钥
        #print("加密订单信息：",self.OI)
        OI_encrypt = binascii.hexlify(rsasign.encrypt_message(pk_M,self.OI)).decode()
        send_info_list.append(OI_encrypt)
        send_info_list.append(H_PI)
        #对DES密钥和支付账号的级联进行加密(结果为十六进制字符串)(这里加密使用的是支付网关的公钥)
        pk_P = binascii.unhexlify(self.Cert_P[1])#获取支付网关的公钥
        # 加密DES密钥信息（这里的sk_1并不是十六进制字符串，而是字节形式，需要转换为十六进制字符串）
        sk_des_enc = binascii.hexlify(rsasign.encrypt_message(pk_P,self.sk_1+self.acc_info)).decode()
        send_info_list.append(sk_des_enc)
        # 对Sign(H(H(OI)||H(PI)))||H(OI)||PI进行加密
        des_enc_info = binascii.hexlify(des.des_encrypt(binascii.unhexlify(self.sk_1),(signature_hex+"**"+H_OI+"**"+self.PI))).decode()
        send_info_list.append(des_enc_info)
        # 发送加密后的订单信息、支付信息、加密后的密钥和签名信息
        self.send_messege_list(s,send_info_list)
        #print("发送信息：",send_info_list)
        receive_info = self.receive_messege(s)#接收支付网关的回复信息
        print("-发送成功，等待商家回复-")
        time.sleep(1)
        print("商家对支付请求信息的验证结果：\n")
        print(receive_info)

    def check_cert(self,Cert):#验证证书的有效性
        message = Cert[0]+Cert[1]#获取被验证方的ID和公钥
        if rsasign.verify_signature(self.pk_CA,message,binascii.unhexlify(Cert[2])):
            return True
        else:
            return False

    def get_cert(self,s):#获取证书
        #为了方便拆分，将需要拼接的信息放到一个列表中
        message = [self.ID_C,self.pk_C_hex]#ID||pk
        self.send_messege_list(s,message)#发送信息给CA
        receive_info = self.receive_messege_list(s)#接收CA的回复信息
        self.Cert_C = receive_info[0:3:]#接受CA发送过来的证书
        self.pk_CA = binascii.unhexlify(receive_info[3])#接受CA发送过来的CA的公钥
        if self.check_cert(self.Cert_C):#验证证书的有效性
            print("证书有效")
            self.send_messege(s,"True")#发送支付请求成功信息
        else:
            print("证书无效")
            self.send_messege(s,"False")#发送支付请求失败信息

    def check_response_order(self,s):#验证商家的发货信息
        rec_info = self.receive_messege_list(s)#接收商家的回复信息
        print("-已接受到商家发货信息,正在验证中-\n")
        time.sleep(1)
        print("商家回复信息：",rec_info)
        self.Cert_M = rec_info[1::]#获取商家的证书
        if self.check_cert(self.Cert_M):#验证商家证书的有效性
            signature_res, H_res = rec_info[0].split("**")#获取商家的签名和回复信息
            # 验证签名
            pk_M = binascii.unhexlify(self.Cert_M[1])#获取商家的公钥
            if rsasign.verify_signature(pk_M,H_res,binascii.unhexlify(signature_res)):
                print("商家发货信息验证成功")
                return True
        else:
            print("商家发货信息验证失败")
            return False
        
    def confirm_receipt(self,s):
        #确认收货
        send_list = []#发送信息列表
        confirm_info = "Confirm receipt"#确认收货信息
        H_confirm = (SHA256.new(confirm_info.encode('utf-8'))).hexdigest()#对确认收货信息进行哈希函数
        signature_hex = binascii.hexlify(rsasign.sign_message(self.sk_C,H_confirm)).decode()#对哈希值进行签名
        send_list.append(signature_hex)
        send_list.append(confirm_info)
        send_list+=self.Cert_C#发送证书
        self.send_messege_list(s,send_list)#发送确认收货信息
        print("-已发送确认收货信息-\n")
        if self.receive_messege(s) == "Confirm receipt success":#接收商家的回复信息
            print("确认收货成功")
            time.sleep(1)
            print("====================交易成功====================")
        else:
            print("确认收货失败")
        
if __name__ == '__main__':
    request_info = "I want to buy something"
    OI_info = "商品名称:遥遥领先；商品数量：1；商品价格：6999"
    PI_info = "支付方式：支付宝；"
    acc = "支付账号：13812345678；支付密码：123456"#支付账号和密码
    # 将请求信息转换为十六进制字符串
    request_info_hex = binascii.hexlify(request_info.encode('utf-8')).decode('utf-8')
    acc_hex = binascii.hexlify(acc.encode('utf-8')).decode('utf-8')
    # 将订单信息和支付信息加入到请求信息中
    cardholder = Cardholder(request_info_hex,OI_info,PI_info,acc)
    print("====================连接CA服务器获取证书====================")
    cardholder.connect_to_CA()
    print("====================作为客户端与商家进行连接====================")
    cardholder.connect_to_marketer()


