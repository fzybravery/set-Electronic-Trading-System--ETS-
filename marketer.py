import RSA_sign as rsasign
import binascii
from socket import *
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import DES_ED as des
import time
# 注意，证书Cert是一个列表，其中分别为 ID 、公钥 、签名


class Marketer:
    def __init__(self):
        # 设置本机作为服务器的IP地址和端口
        self.address = '127.0.0.1'
        self.port = 25625

        #相关支付信息
        self.OI = ""#订单信息
        self.PI = ""#支付信息
        self.acc = ""#账户信息
        self.AuthREQ = "请求支付"#授权请求信息

        # 公钥密码
        self.sk_M,self.pk_M = rsasign.generate_keypair()
        # 十六进制字符串形式的公私钥
        self.sk_M_hex = binascii.hexlify(self.sk_M).decode()
        self.pk_M_hex = binascii.hexlify(self.pk_M).decode()
        
        # ID信息(随机数)
        self.ID_M = 'marketer'

        # DES密钥
        self.sk_1 = -1#保存持卡人的DES密钥
        self.sk_2 = binascii.hexlify(get_random_bytes(8)).decode()#保存商家的DES密钥
        self.sk_3 = -1#保存支付网关的DES密钥

        # 证书
        self.Cert_C = []#初始化为0
        self.Cert_M = []#商家的证书
        self.Cert_P = []#支付网关的证书

        # 商家作为中转，暂时存储持卡人发送给支付网关的加密信息
        self.enc_sk_1 = ""#保存由持卡人的公钥加密的持卡人DES密钥
        self.enc_info = ""#保存由支付网关的公钥加密的支付信息

        # 商家在接受到支付授权之后，暂存持卡人发行行的密钥信息，以及CapTok安全令牌的签名加密信息
        self.enc_sk4_acc = ""
        self.enc_sign_captok = ""


    def connect_to_CA(self):
        #连接CA服务器获取证书
        server_HOST = '127.0.0.1'
        server_PORT = 10086
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((server_HOST,server_PORT))
        self.get_cert(s)#获取证书
        s.close()#关闭与CA的连接


    def connection(self):
        # 连接持卡人、支付网关
        # 作为服务器等待持卡人连接
        # 创建套接字
        server_socket = socket(AF_INET, SOCK_STREAM)
        # 绑定IP地址和端口
        server_socket.bind((self.address, self.port))
        # 监听连接
        server_socket.listen(1)
        # 等待持卡人连接
        print("*********正在与持卡人进行连接*********\n")
        while True:
            try:
                conn, addr = server_socket.accept()
                print("---持卡人连接成功！---\n")
                break
            except Exception as e:
                print(f"---持卡人连接失败，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试

        # 作为客户端与支付网关连接
        server_HOST = '127.0.0.1'
        server_PORT = 36956

        print("**********等待支付网关连接中...**********\n")

        while True:
            try:
                s = socket(AF_INET,SOCK_STREAM)
                s.connect((server_HOST,server_PORT))
                print("---支付网关连接成功！---\n")
                break
            except Exception as e:
                print(f"---支付网关连接失败，重试中... 错误: {e}---\n")
                time.sleep(1)  # 等待1秒后重试
        
        print("##########连接建立成功开始进行支付##########\n")
        time.sleep(1)
        # 开始交易过程
        print("---等待接收支付网关证书---\n")
        self.Cert_P = self.receive_messege_list(s)#接收支付网关的证书
        print("支付网关证书：",self.Cert_P)
        time.sleep(1)
        print("---等待验证支付网关证书---\n")
        if self.check_cert(self.Cert_P):#验证证书的有效性
            print("支付网关证书有效")
            print("---等待接受持卡人的支付请求---\n")
            time.sleep(1)
            self.respond_to_cardholder(conn)#回复购买请求
            print("---等待持卡人的支付信息和订单信息---\n")
            time.sleep(1)
            if self.check_cardholder_info(conn):#验证持卡人的订单信息
                print("---向支付网关请求支付授权---\n")
                time.sleep(1)
                self.send_messege(s,"I want to request for payment authorization.")
                while True:
                    # 等待支付网关的回复
                    response = self.receive_messege(s)
                    if response == "Please send me your payment authorization request.":
                       break
                self.request_payment_authorization(s)#向支付网关请求支付授权 
                print("---等待支付网关的支付授权---\n")
                time.sleep(1)
                if self.check_payment_authorization(s):#验证支付网关的支付授权信息
                    print("---向商家发送回应订单并发货---\n")
                    self.response_to_an_order(conn)#向商家回应订单并发货
                    print("-发送完成,等待持卡人确认收货-\n")
                    time.sleep(1)
                    if self.check_confirmation(conn):#确认收货
                        # 确认收货信息无误，开始请款
                        print("---确认收货信息无误，开始请款---\n")
                        time.sleep(1)
                        self.request_payout(s)# 向支付网关发送请款请求
                        print("---请款请求发送成功，等待支付网关回复---\n")
                        time.sleep(1)
                        if self.check_payout(s):#验证支付网关的请款信息
                            self.send_messege(conn,"Confirm receipt success")#发送支付成功信息
                            print("---支付完成---\n")
                            print("====================交易成功====================\n")
                    
            else:
                print("订单信息无效")
        else:
            print("支付网关证书无效")

        #conn.close()#关闭与持卡人的连接
        #s.close()#关闭与支付网关的连接

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
        message = [self.ID_M,self.pk_M_hex]#ID||pk
        self.send_messege_list(s,message)#发送信息给CA
        receive_info = self.receive_messege_list(s)#接收CA的回复信息
        self.Cert_M = receive_info[0:3:]#接受CA发送过来的证书
        self.pk_CA = binascii.unhexlify(receive_info[3])#接受CA发送过来的CA的公钥
        if self.check_cert(self.Cert_M):#验证证书的有效性
            print("证书有效")
            self.send_messege(s,"True")#发送支付请求成功信息
        else:
            print("证书无效")
            self.send_messege(s,"False")#发送支付请求失败信息

    def respond_to_cardholder(self,s):#回应持卡人购买请求
        send_list = []#发送信息的列表
        request_buy = self.receive_messege(s)#接受持卡人的购买请求
        print("持卡人购买请求：",request_buy)
        print("---回应持卡人购买请求并等待其验证结果---\n")
        time.sleep(1)
        #创建一个sha256的哈希对象
        H_req = SHA256.new(request_buy.encode('utf-8'))#对获取的购买请求进行哈希函数
        H_req_hex = H_req.hexdigest()#将哈希值转换为十六进制字符串
        signature = rsasign.sign_message(self.sk_M,H_req_hex)#用本机的私钥对消息进行签名
        signature_hex = binascii.hexlify(signature).decode()#将签名转换为十六进制字符串
        send_list.append(signature_hex)#添加签名到发送信息列表
        send_list += self.Cert_M#添加商家的证书到发送信息列表
        send_list += self.Cert_P#添加支付网关的证书到发送信息列表
        self.send_messege_list(s,send_list)#发送签名和证书给持卡人
        temp_re = self.receive_messege(s)#接收支付网关的回复信息
        print("发送成功且持卡人回复信息：",temp_re)

    def check_cardholder_info(self,s):#验证持卡人信息
        # 接收持卡人发送的签名和证书
        print("-获取的持卡人的信息如下-\n")
        self.Cert_C = self.receive_messege_list(s)
        print("持卡人证书及其验证结果：\n")
        print(self.Cert_C)
        if self.check_cert(self.Cert_C):#验证证书的有效性
            print("持卡人证书验证有效\n")
            rec_info_list = self.receive_messege_list(s)#接收持卡人发送的订单信息和支付信息
            print("订单信息及其验证结果：\n")
            print(rec_info_list,"\n")
            # 解密订单信息
            OI_enc = rec_info_list[1]#这里的加密信息是十六进制字符串形式
            self.OI = rsasign.decrypt_message(self.sk_M,binascii.unhexlify(OI_enc)) #解密订单信息
            #对订单信息进行哈希函数
            H_OI = (SHA256.new(self.OI.encode('utf-8'))).hexdigest()
            H_PI = rec_info_list[2]#获取支付信息的哈希值
            #对上述两个哈希值进行哈希函数
            H_OI_PI = (SHA256.new((H_OI+H_PI).encode('utf-8'))).hexdigest()
            #验证签名
            pk_C = binascii.unhexlify(self.Cert_C[1])#获取持卡人的公钥
            signature_H = rec_info_list[0] #H_OI_PI的签名
            if rsasign.verify_signature(pk_C,H_OI_PI,binascii.unhexlify(signature_H)):
                print("持卡人订单信息验证成功！")
                # 回复持卡人上述信息的验证结果
                self.enc_sk_1 = rec_info_list[3]#保存由持卡人的公钥加密的持卡人DES密钥
                self.enc_info = rec_info_list[4]#保存由支付网关的公钥加密的支付信息
                self.send_messege(s,"Verification success!")#发送验证成功信息
                return True
            else:
                print("持卡人订单信息验证失败！")
        else:
            print("持卡人证书无效")
            
    def request_payment_authorization(self,s):#请求支付授权
        # 商家向支付网关请求支付授权
        # 使用支付网关公钥加密商家的DES密钥
        print("-支付授权请求发送成功等待支付网关回复-\n")
        time.sleep(1)
        request_list = []#请求信息的列表
        pk_P = binascii.unhexlify(self.Cert_P[1])#获取支付网关的公钥
        enc_sk_2 = binascii.hexlify(rsasign.encrypt_message(pk_P,self.sk_2)).decode()#加密商家的DES密钥
        request_list.append(enc_sk_2)
        # 对支付授权请求进行哈希函数和签名
        H_AuthREQ = (SHA256.new(self.AuthREQ.encode('utf-8'))).hexdigest()
        signature_AuthREQ = rsasign.sign_message(binascii.unhexlify(self.sk_M_hex),H_AuthREQ)
        signature_AuthREQ_hex = binascii.hexlify(signature_AuthREQ).decode()
        info = signature_AuthREQ_hex+"**"+self.AuthREQ
        enc_signature = binascii.hexlify(des.des_encrypt(binascii.unhexlify(self.sk_2),info)).decode()
        request_list.append(enc_signature)#发送哈希值的签名和请求信息的级联
        request_list.append(self.enc_sk_1)#发送用支付网关公钥加密的持卡人的DES密钥和账户信息
        request_list.append(self.enc_info)#发送用支付网关公钥加密的支付信息
        # 分别将商家和持卡人的证书列表添加到请求信息列表中
        request_list += self.Cert_M
        request_list += self.Cert_C
        self.send_messege_list(s,request_list)#发送请求信息
        payment_response = self.receive_messege(s)#接收支付网关的回复信息
        print("支付网关回复信息：\n",payment_response)
        
    def check_payment_authorization(self,s):#验证支付授权信息
        # 接受支付网关的支付授权信息并验证
        Auth_info = self.receive_messege_list(s)#接收支付网关发送的支付授权信息
        print("-已接受支付网关的支付授权信息,正在验证中-\n")
        time.sleep(1)


        self.Cert_P = Auth_info[4::]#支付网关证书
        print("支付网关证书及其验证结果：\n",self.Cert_P)
        if self.check_cert(self.Cert_P):#验证证书的有效性
            print("支付网关证书有效\n")
            # 解密支付网关密钥
            enc_sk3 = Auth_info[0]#加密的支付网关的DES密钥
            self.sk_3 = rsasign.decrypt_message(self.sk_M,binascii.unhexlify(enc_sk3))
            # 解密验证支付授权信息
            des_enc_AuthRES = Auth_info[1]#加密的支付授权信息
            des_dec_AuthRES = des.des_decrypt(binascii.unhexlify(self.sk_3),binascii.unhexlify(des_enc_AuthRES))
            signature_AuthRES,AuthRES = des_dec_AuthRES.split("**")
            H_AuthRES = (SHA256.new(AuthRES.encode('utf-8'))).hexdigest()
            pk_P = binascii.unhexlify(self.Cert_P[1])#获取支付网关的公钥
            if rsasign.verify_signature(pk_P,H_AuthRES,binascii.unhexlify(signature_AuthRES)):
                print("支付授权信息验证成功！\n")
                # 存储持卡人发行行的密钥信息，以及CapTok安全令牌的加密信息
                self.enc_sk4_acc = Auth_info[2]#保存由支付网关的公钥加密的持卡人发行行的密钥信息
                self.enc_sign_captok = Auth_info[3]#保存由支付网关的公钥加密的CapTok安全令牌的签名加密信息
                # 回复支付网关支付授权信息的验证结果
                self.send_messege(s,"True")
                return True
            else:
                print("支付授权信息的签名验证失败！\n")
                return False
        else:
            print("支付网关证书无效")
            return False

    def response_to_an_order(self,s):#回复订单并发货
        # 向持卡人回应订单并发货
        send_list = []#发送信息的列表
        response_info = 'Verification success! Your order has been sent to the delivery.'
        H_res = (SHA256.new(response_info.encode('utf-8'))).hexdigest()
        signature_response = rsasign.sign_message(self.sk_M,H_res)
        send_list.append((binascii.hexlify(signature_response).decode()+"**"+H_res))#发送签名
        send_list+=self.Cert_M#添加商家的证书
        print(send_list)
        self.send_messege_list(s,send_list)#发送回复信息

    def check_confirmation(self,s):
        # 验证持卡人的确认收货信息
        confirmation_info = self.receive_messege_list(s)
        print("-已接受持卡人的确认收货信息,正在验证中-\n")
        time.sleep(1)
        # 验证签名
        self.Cert_C = confirmation_info[2::]
        if self.check_cert(self.Cert_C):#验证证书的有效性
            print("持卡人证书验证有效\n")
            signature_confirm = confirmation_info[0]
            confirmation = confirmation_info[1]
            H_confirm = (SHA256.new(confirmation.encode('utf-8'))).hexdigest()
            pk_C = binascii.unhexlify(self.Cert_C[1])#获取持卡人的公钥
            if rsasign.verify_signature(pk_C,H_confirm,binascii.unhexlify(signature_confirm)):
                print("确认收货信息验证成功！\n")  
                return True
            else:
                print("确认收货信息的签名验证失败！\n")
                return False
        else:
            print("验证收获信息时持卡人证书无效")
            return False

    def request_payout(self,s):
        # 向支付网关请求支付
        send_list = []#发送信息的列表
        sk_5 = binascii.hexlify(get_random_bytes(8)).decode()#生成用于请款的密钥
        # 加密请款密钥
        enc_sk_5 = binascii.hexlify(rsasign.encrypt_message(binascii.unhexlify(self.Cert_P[1]),sk_5)).decode()
        send_list.append(enc_sk_5)#发送加密的请款密钥
        # 加密请款信息
        CapREQ = "Transaction successful! Please send me your payment."#支付请求信息
        H_CapREQ = (SHA256.new(CapREQ.encode('utf-8'))).hexdigest()#对支付请求信息进行哈希函数
        signature_CapREQ = binascii.hexlify(rsasign.sign_message(self.sk_M,H_CapREQ)).decode()
        info = signature_CapREQ+"**"+CapREQ
        enc_info = binascii.hexlify(des.des_encrypt(binascii.unhexlify(sk_5),info)).decode()
        send_list.append(enc_info)#发送加密的请款信息
        # 发送之前接受的支付网关的支付授权信息
        send_list.append(self.enc_sk4_acc)
        send_list.append(self.enc_sign_captok)
        # 发送商家的证书
        send_list += self.Cert_M
        self.send_messege_list(s,send_list)#发送请款请求信息
        if self.receive_messege(s) == "Verification success!":#验证支付网关的回复信息
            print("-请款请求发送成功,等待支付网关回复-\n")
            time.sleep(1)
            # 接收支付网关的回复信息
        else:
            print("-请款请求发送失败,请检查网络连接或支付网关是否正常-\n")

    def check_payout(self,s):
        # 验证支付信息
        payout_info = self.receive_messege_list(s)
        print("-已接受支付网关的请款信息,正在验证中-\n")
        time.sleep(1)
        # 验证证书
        self.Cert_P = payout_info[2::]
        if self.check_cert(self.Cert_P):#验证证书的有效性
            print("支付网关证书验证有效\n")
            # 解密请款密钥
            enc_sk6 = payout_info[0]
            sk_6 = rsasign.decrypt_message(self.sk_M,binascii.unhexlify(enc_sk6))
            # 解密请款信息
            des_enc_CapRES = payout_info[1]
            des_dec_CapRES = des.des_decrypt(binascii.unhexlify(sk_6),binascii.unhexlify(des_enc_CapRES))
            signature_CapRES,CapRES = des_dec_CapRES.split("**")
            H_CapRES = (SHA256.new(CapRES.encode('utf-8'))).hexdigest()
            pk_P = binascii.unhexlify(self.Cert_P[1])#获取支付网关的公钥
            if rsasign.verify_signature(pk_P,H_CapRES,binascii.unhexlify(signature_CapRES)):
                print("请款信息验证成功！\n")
                # 回复支付网关请款信息的验证结果
                self.send_messege(s,"Payment success.")
                return True
            else:
                print("请款信息的签名验证失败！\n")
                return False
        else:
            print("请款信息时支付网关证书无效")
            return False

if __name__ == '__main__':
    marketer = Marketer()
    print("====================连接CA服务器获取证书====================")
    marketer.connect_to_CA()
    print("====================连接持卡人和支付网关====================")
    marketer.connection()

