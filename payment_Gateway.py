import RSA_sign as rsasign
import binascii
from socket import *
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import DES_ED as des
import time
import CapToken as CapTok_gen


class payment_Gateway:
    def __init__(self):
        # 设置本机作为服务器的IP地址和端口
        self.address = '127.0.0.1'
        self.port = 36956

        # 信息(均为十六进制字符串形式)
        self.ID_P = 'payment_gateway'# ID信息

        # RSA的公私钥
        self.sk_P,self.pk_P = rsasign.generate_keypair()
        # 十六进制字符串形式的公私钥
        self.sk_P_hex = binascii.hexlify(self.sk_P).decode()
        self.pk_P_hex = binascii.hexlify(self.pk_P).decode()


        # DES密钥
        self.sk_1 = -1#保存持卡人的DES密钥
        self.sk_2 = -1#保存商家的DES密钥
        self.sk_3 = binascii.hexlify(get_random_bytes(8)).decode()#保存支付网关的DES密钥
        
        # 证书
        self.Cert_C = []#初始化为0
        self.Cert_M = []#商家的证书
        self.Cert_P = []#支付网关的证书
        self.Cert_B = []#持卡人发行行的证书

        # 持卡人的账户信息
        self.acc = ""

        # 持卡人发行行的安全令牌
        self.CapToken = ""

        # 保存持卡人发行行的支付授权信息便于后于验证
        self.enc_sk4_acc = ""
        self.enc_Captok = ""


    def connect_to_CA(self):
        #连接CA服务器获取证书
        server_HOST = '127.0.0.1'
        server_PORT = 10086
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((server_HOST,server_PORT))
        self.get_cert(s)#获取证书
        s.close()#关闭与CA的连接
    

    def connection(self):
        # 作为服务器等待商家连接
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.bind((self.address, self.port))
        server_socket.listen(1)
        print("*********正在与商家进行连接*********\n")
        while True:
            try:
                conn, addr = server_socket.accept()
                print("---商家连接成功！---\n")
                self.send_messege_list(conn, self.Cert_P)
                break  # 成功连接后退出循环
            except Exception as e:
                print(f"---商家连接失败，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试

        # 作为客户端与持卡人发行行建立连接
        server_HOST = '127.0.0.1'
        server_PORT = 36669

        print("---等待持卡人发行行连接中......---\n")

        while True:
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((server_HOST, server_PORT))
                print("---持卡人发行行连接成功！---\n")
                break  # 成功连接后退出循环
            except Exception as e:
                print(f"---持卡人发行行连接成功，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试
        print("##########连接建立成功开始进行支付##########\n")
        time.sleep(1)
        # 开始进行支付
        print("---等待接收持卡人发行行证书---\n")
        self.Cert_B = self.receive_messege_list(s)#接收支付网关的证书
        print("持卡人发行行证书：",self.Cert_B)
        print("---等待验证持卡人发行行证书---\n")
        time.sleep(1)
        if self.check_cert(self.Cert_B):
            print("证书有效")
        else:
            print("证书无效")
        

        #循环等待商家请求支付授权
        print("---等待商家请求支付授权---\n")
        time.sleep(1)
        while True:
            if self.receive_messege(conn) == "I want to request for payment authorization.":
                #print("等待商家请求支付授权")
                self.send_messege(conn,"Please send me your payment authorization request.")
                #验证商家发来的支付授权请求
                if self.check_AuthREQ(conn):
                    # 支付授权回应
                    # 向持卡人发行行请求支付授权
                    print("---向持卡人发行行请求支付授权---\n")
                    time.sleep(1)
                    self.request_payment_Auth(s)
                    print("---等待持卡人发行行的支付授权回应---\n")
                    time.sleep(1)
                    self.check_AuthRES(s)#验证持卡人发行行的支付授权回应
                    print("---向商家发送支付授权请求回应中---\n")
                    time.sleep(1)
                    self.response_payment_Auth(conn)#将支付授权发送给商家
                    break
        
        if self.check_payout_request(conn):
            # 验证商家请款信息的真实性
            print("-商家请款信息验证成功,正在向持卡人发行行请求支付---\n")
            time.sleep(1)
            self.request_payout(s)#向持卡人发行行请求支付
            print("-等待持卡人发行行的支付回应---\n")
            time.sleep(1)
            if self.check_payout(s):
                # 验证持卡人发行行的支付回应
                self.payout_response(conn)#向商家发送支付回应
                print("-成功向商家发送请款请求,等待其验证结果中-\n")
                time.sleep(1)
                if self.receive_messege(conn) == "Payment success.":
                    print("---支付成功---\n")
                    print("====================交易结束=====================\n")
                else:
                    print("---支付失败---\n")
            else:
                print("---支付失败---\n")
        else:
            print("---请款信息无效---\n")
        s.close()#关闭与持卡人发行行的连接
        conn.close()#关闭与商家的连接
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
        data = s.recv(4096).decode()
        #将接受到的信息按"||"分割成列表
        return data.split("||")
    
    def receive_messege(self,s):#接收消息
        data = s.recv(4096).decode()
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
        message = [self.ID_P,self.pk_P_hex]#ID||pk
        self.send_messege_list(s,message)#发送信息给CA
        receive_info = self.receive_messege_list(s)#接收CA的回复信息
        self.Cert_P = receive_info[0:3:]#接受CA发送过来的证书
        self.pk_CA = binascii.unhexlify(receive_info[3])#接受CA发送过来的CA的公钥
        if self.check_cert(self.Cert_P):#验证证书的有效性
            print("证书有效")
            self.send_messege(s,"True")#发送支付请求成功信息
        else:
            print("证书无效")
            self.send_messege(s,"False")#发送支付请求失败信息

    def check_AuthREQ(self,s):#验证商家发来的支付授权请求
        print("-成功接受商家的授权请求,正在验证信息中-\n")
        time.sleep(1)
        # 接收商家发来的支付授权请求
        rec_message = self.receive_messege_list(s)
        # 验证商家发来的证书有效性
        self.Cert_M = rec_message[4:7:]
        print("-商家的证书：\n",self.Cert_M)
        self.Cert_C = rec_message[7:10:]
        print("-持卡人的证书：\n",self.Cert_C)
        if self.check_cert(self.Cert_M) and self.check_cert(self.Cert_C):
            print("商家发送的商家证书和持卡人证书均有效\n")
            # 获取商家的DES密钥
            enc_sk_2 = rec_message[0]
            self.sk_2 = rsasign.decrypt_message(self.sk_P,binascii.unhexlify(enc_sk_2))
            print("商家密钥获取成功\n")
            # 验证商家的支付授权请求的真实性
            enc_info = rec_message[1]#使用sk_2加密的授权信息
            info = des.des_decrypt(binascii.unhexlify(self.sk_2),binascii.unhexlify(enc_info))
            signature_AuthREQ_hex , AuthREQ = info.split("**") 
            H_AuthREQ = (SHA256.new(AuthREQ.encode('utf-8'))).hexdigest()
            pk_M = binascii.unhexlify(self.Cert_M[1])
            if rsasign.verify_signature(pk_M,H_AuthREQ,binascii.unhexlify(signature_AuthREQ_hex)):
                print("商家的支付授权请求有效\n")
                # 获取持卡人的账户信息和DES密钥
                enc_sk_1acc = rec_message[2]
                #print("enc_sk_1acc:",enc_sk_1acc)
                dec_sk_1acc = rsasign.decrypt_message(self.sk_P,binascii.unhexlify(enc_sk_1acc))
                #print("dec_sk_1acc:",type(dec_sk_1acc))
                self.sk_1 = dec_sk_1acc[0:16:]#持卡人的DES密钥
                self.acc = dec_sk_1acc[16::]#持卡人的账户信息
                # 解密验证支付请求信息的签名
                enc_info_OIPI = rec_message[3]#使用sk_1加密的支付请求信息
                info_OIPI = des.des_decrypt(binascii.unhexlify(self.sk_1),binascii.unhexlify(enc_info_OIPI))
                signature_H_OIPI , H_OI , PI = info_OIPI.split("**") 
                H_PI = (SHA256.new(PI.encode('utf-8'))).hexdigest()
                H_OIPI = (SHA256.new((H_OI+H_PI).encode('utf-8'))).hexdigest()
                pk_C = binascii.unhexlify(self.Cert_C[1])
                if rsasign.verify_signature(pk_C,H_OIPI,binascii.unhexlify(signature_H_OIPI)):
                    print("商家的支付授权请求验证成功\n")
                    self.send_messege(s,"Verify Success")#发送支付请求成功信息
                    return True
                else:
                    print("持卡人的支付信息无效")
                    return False
            else:
                print("商家的支付授权请求无效")
                self.send_messege(s,"支付授权请求无效，请重新发送")#发送支付请求失败信息
                return False
        else:
            print("商家发送的证书无效")
            self.send_messege(s,"证书无效，请重新发送")#发送支付请求失败信息
            return False
    
    def request_payment_Auth(self,s):
        # 向持卡人发行行请求支付授权
        send_list = []#发送信息的列表
        pk_B = binascii.unhexlify(self.Cert_B[1])#获取持卡人发行行的公钥
        enc_acc = rsasign.encrypt_message(pk_B,(self.sk_3+self.acc))#对账户信息进行加密（利用发行行的公钥）
        send_list.append(binascii.hexlify(enc_acc).decode())#添加加密后的账户信息(十六进制字符串形式)
        # 发送商家的证书、持卡人证书、支付请求信息
        Auth_req = "I have check the payment request and agree to authorize the payment."#支付授权请求信息
        H_Auth_req = (SHA256.new(Auth_req.encode('utf-8'))).hexdigest()#对支付授权信息进行哈希
        signature_Auth_req = binascii.hexlify(rsasign.sign_message(self.sk_P,H_Auth_req)).decode()#对支付授权信息进行签名
        des_enc_sar = des.des_encrypt(binascii.unhexlify(self.sk_3),(signature_Auth_req+"**"+Auth_req))#利用支付网关的密钥对签名进行加密
        send_list.append(binascii.hexlify(des_enc_sar).decode())#添加加密后的签名(十六进制字符串形式)
        send_list += self.Cert_P#添加支付网关的证书
        self.send_messege_list(s,send_list)#发送信息给持卡人发行行
        # 接收持卡人发行行的回复信息
        print("-成功向持卡人发行行发送支付授权请求,等待其验证结果中-\n")
        time.sleep(1)
        rec_message = self.receive_messege(s)
        if rec_message == "True":
            print("验证成功")
        else:
            print("验证失败")


    def check_AuthRES(self,s):
        # 接收持卡人发行行的支付授权回应
        rec_message = self.receive_messege_list(s)
        print("-成功接收持卡人发行行的支付授权,正在验证信息中-\n")
        time.sleep(1)
        self.Cert_B = rec_message[3::]
        if self.check_cert(self.Cert_B):
            # 验证持卡人发行行的支付授权回应的真实性
            enc_acc = rec_message[0]
            acc_sk4 = rsasign.decrypt_message(self.sk_P,binascii.unhexlify(enc_acc))
            acc_rec = acc_sk4[16::]#解密后的账户信息
            if acc_rec == self.acc:
                print("持卡人发行行的账户信息有效\n")
                self.sk_4 = acc_sk4[0:16:]#保存商家的DES密钥
                # 解密验证持卡人发行行的支付授权响应
                des_dec_sar = des.des_decrypt(binascii.unhexlify(self.sk_4),binascii.unhexlify(rec_message[1]))
                signature_Auth_res , Auth_res = des_dec_sar.split("**")
                H_Auth_res = (SHA256.new(Auth_res.encode('utf-8'))).hexdigest()
                pk_B = binascii.unhexlify(self.Cert_B[1])
                if rsasign.verify_signature(pk_B,H_Auth_res,binascii.unhexlify(signature_Auth_res)):
                    self.AuthRES = Auth_res#保存持卡人发行行的支付授权回应
                    print("持卡人发行行的支付授权回应有效\n")
                    # 验证持卡人发行行发送的令牌信息
                    des_dec_token = des.des_decrypt(binascii.unhexlify(self.sk_4),binascii.unhexlify(rec_message[2]))
                    print("des_dec_token:",des_dec_token)
                    signature_token, token = des_dec_token.split("**")
                    H_token = (SHA256.new(token.encode('utf-8'))).hexdigest()
                    if rsasign.verify_signature(pk_B,H_token,binascii.unhexlify(signature_token)) and CapTok_gen.verify_cap_token(self.sk_4,token):
                        self.CapToken = token#保存持卡人发行行的安全令牌
                        print("持卡人发行行的令牌信息有效\n")
                        # 发送支付授权回应
                        print("-支付授权验证成功-\n")
                        self.send_messege(s,"True")
                        return True
                else:
                    print("持卡人发行行的支付授权回应无效")
                    return False
        else:
            print("持卡人发行行的支付授权回应无效")
            return False

    def response_payment_Auth(self,s):
        # 向商家发送支付授权请求的回应
        print("-已向商家发送支付授权,等待其验证结果中-\n")
        time.sleep(1)

        send_list = []#发送信息的列表
        pk_M = binascii.unhexlify(self.Cert_M[1])#获取商家的公钥
        # 加密支付网关的密钥
        enc_sk3 = binascii.hexlify(rsasign.encrypt_message(pk_M,self.sk_3)).decode()
        send_list.append(enc_sk3)#添加加密后的支付网关的密钥
        # 签名加密支付授权
        AuthRES = "I authorize the payment."#支付授权回应信息
        H_AuthRES = (SHA256.new(AuthRES.encode('utf-8'))).hexdigest()#对支付授权回应信息进行哈希
        signature_AuthRES = binascii.hexlify(rsasign.sign_message(self.sk_P,H_AuthRES)).decode()#对支付授权回应信息进行签名
        des_enc_AuthRES = des.des_encrypt(binascii.unhexlify(self.sk_3),(signature_AuthRES+"**"+AuthRES))#利用商家的密钥对签名进行加密
        send_list.append(binascii.hexlify(des_enc_AuthRES).decode())#添加加密后的签名(十六进制字符串形式)
        # 加密发送持卡人支付行的密钥信息
        enc_sk_4acc = binascii.hexlify(rsasign.encrypt_message(self.pk_P,self.sk_4+self.acc)).decode()
        send_list.append(enc_sk_4acc)#添加加密后的账户信息(十六进制字符串形式)
        # 签名加密持卡人发行行的安全令牌信息
        H_Captok = (SHA256.new(self.CapToken.encode('utf-8'))).hexdigest()
        signature_Captok = binascii.hexlify(rsasign.sign_message(self.sk_P,H_Captok)).decode()
        des_enc_Captok = des.des_encrypt(binascii.unhexlify(self.sk_4),(signature_Captok+"**"+self.CapToken))
        self.enc_Captok = binascii.hexlify(des_enc_Captok).decode()# 保存信息方便后续验证
        self.enc_sk4_acc = enc_sk_4acc# 保存信息方便后续验证
        send_list.append(binascii.hexlify(des_enc_Captok).decode())#添加加密后的签名(十六进制字符串形式)
        send_list += self.Cert_P#添加支付网关证书
        self.send_messege_list(s,send_list)#发送信息给商家
        # 接收商家的回复信息
        rec_message = self.receive_messege(s)
        if rec_message == "True":
            print("商家验证成功\n")
        else:
            print("商家验证失败\n")

    def check_payout_request(self,s):
        # 验证商家请款信息的真实性
        print("-商家请款信息验证中-\n")
        time.sleep(1)
        
        rec_info = self.receive_messege_list(s)
        # 验证商家发来的证书有效性
        print(rec_info)
        self.Cert_M = rec_info[4:7:]
        if self.check_cert(self.Cert_M):
            print("商家的证书有效\n")
            # 解密获得请款密钥
            enc_sk5 = rec_info[0]
            sk5 = rsasign.decrypt_message(self.sk_P,binascii.unhexlify(enc_sk5))
            # 验证请款请求的真实性
            enc_info = rec_info[1]
            info = des.des_decrypt(binascii.unhexlify(sk5),binascii.unhexlify(enc_info))
            signature_CapREQ , CapREQ = info.split("**")
            H_CapREQ = (SHA256.new(CapREQ.encode('utf-8'))).hexdigest()
            pk_M = binascii.unhexlify(self.Cert_M[1])
            if rsasign.verify_signature(pk_M,H_CapREQ,binascii.unhexlify(signature_CapREQ)):
                print("商家的请款请求有效\n")
                # 验证支付授权信息的有效性
                enc_info_accsk4 = rec_info[2]
                enc_info_captok = rec_info[3]
                if enc_info_accsk4 == self.enc_sk4_acc and enc_info_captok == self.enc_Captok:
                    print("商家的请款信息有效\n")
                    self.send_messege(s,"Verification success!")
                    return True
                else:
                    print("商家的请款信息无效")
                    return False
            else:
                print("商家的请款请求无效")
                return False
        else:
            print("商家的证书无效")
            return False

    def request_payout(self,s):
        # 向持卡人发行行请求请款
        print("-已向持卡人发行行请求请款,等待其验证结果中-\n")
        time.sleep(1)
        send_list = []#发送信息的列表
        CapREQ = "you can pay to marketer."
        H_CapREQ = (SHA256.new(CapREQ.encode('utf-8'))).hexdigest()
        signature_CapREQ = binascii.hexlify(rsasign.sign_message(self.sk_P,H_CapREQ)).decode()
        des_enc_CapREQ = des.des_encrypt(binascii.unhexlify(self.sk_4),(signature_CapREQ+"**"+CapREQ))
        send_list.append(binascii.hexlify(des_enc_CapREQ).decode())#添加加密后的签名(十六进制字符串形式)
        send_list += self.Cert_P#添加支付网关证书
        self.send_messege_list(s,send_list)#发送信息给持卡人发行行
        print("-成功向持卡人发行行发送请款请求,等待其验证结果中-\n")
        time.sleep(1)
        rec_message = self.receive_messege(s)
        if rec_message == "True":
            print("验证成功")
        else:
            print("验证失败")
    
    def check_payout(self,s):
        # 接收持卡人发行行的请款回应
        print("-成功接收持卡人发行行的请款,正在验证信息中-\n")
        time.sleep(1)
        rec_info = self.receive_messege_list(s)
        # 验证持卡人发行行的请款回应的真实性
        self.Cert_B = rec_info[1::]
        if self.check_cert(self.Cert_B):
            print("持卡人发行行的证书有效\n")
            # 解密获得请款密钥
            enc_info = rec_info[0]
            dec_CapRES = des.des_decrypt(binascii.unhexlify(self.sk_4),binascii.unhexlify(enc_info))
            signature_CapRES , CapRES = dec_CapRES.split("**")
            H_CapRES = (SHA256.new(CapRES.encode('utf-8'))).hexdigest()
            pk_B = binascii.unhexlify(self.Cert_B[1])
            if rsasign.verify_signature(pk_B,H_CapRES,binascii.unhexlify(signature_CapRES)):
                print("持卡人发行行的请款回应有效\n")
                self.send_messege(s,"True")#发送请款成功信息
                return True
            else:
                print("持卡人发行行的请款回应无效")
                return False
        else:
            print("持卡人发行行的证书无效")
            return False

    def payout_response(self,s):
        # 向商家发送请款请求的回应
        print("-已向商家发送请款请求,等待其验证结果中-\n")
        time.sleep(1)
        send_list = []#发送信息的列表
        sk_6 = binascii.hexlify(get_random_bytes(8)).decode()#生成随机的请款密钥
        pk_M = binascii.unhexlify(self.Cert_M[1])#获取商家的公钥
        enc_sk6 = binascii.hexlify(rsasign.encrypt_message(pk_M,sk_6)).decode()
        send_list.append(enc_sk6)#添加加密后的请款密钥
        # 签名加密请款信息
        PayoutREQ = "The payment has been made."
        H_PayoutREQ = (SHA256.new(PayoutREQ.encode('utf-8'))).hexdigest()
        signature_PayoutREQ = binascii.hexlify(rsasign.sign_message(self.sk_P,H_PayoutREQ)).decode()
        des_enc_PayoutREQ = des.des_encrypt(binascii.unhexlify(sk_6),(signature_PayoutREQ+"**"+PayoutREQ))
        send_list.append(binascii.hexlify(des_enc_PayoutREQ).decode())#添加加密后的签名(十六进制字符串形式)
        send_list += self.Cert_P#添加支付网关证书
        self.send_messege_list(s,send_list)#发送信息给商家
        

                

if __name__ == '__main__':
    pay_gatway = payment_Gateway()
    print("====================连接CA服务器获取证书====================")
    pay_gatway.connect_to_CA()
    print("====================连接商家=======================")
    pay_gatway.connection()


