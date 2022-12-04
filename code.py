import base64
import codecs
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
import traceback
from binascii import b2a_hex, a2b_hex
import base64
import frida
import requests
import urllib3
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
import cv2
from utils import *
import configparser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

 
# 定时器
class Timer:
    def __init__(self, startTime):
        self.buy_time = datetime.datetime.strptime(startTime, "%Y-%m-%d %H:%M:%S.%f")
        self.buy_time_ms = int(time.mktime(self.buy_time.timetuple()) * 1000.0 + self.buy_time.microsecond / 1000)

    # 本地时间
    def local_time(self):
        return int(round(time.time() * 1000))

    # 等待定时任务
    def start(self, advance=20):
        if advance:
            log('正在等待到达设定时间:{}，提前{}秒'.format(self.buy_time, advance))
        else:
            log('正在等待到达设定时间:{}'.format(self.buy_time))
        while True:
            if self.local_time() + advance >= self.buy_time_ms:
                log('时间到达，开始执行……')
                break


class ZmyySeckill:
    def __init__(self, config,signature,sessionId, proxy=None, headers_file='headers.txt'):
        self.config = config
        self.t = Timer(self.config['zhimiao']['startTime'])
        self.session = requests.session()
        # 默认代理
        self.proxy = proxy
        self.guid = ""
        self.key = signature
        self.sessionId="ASP.NET_SessionId="+sessionId
        # 间隔时间
        self.interval = 0.5

        # 读取headers
        self.headers = {}
        f = open(headers_file, 'r', encoding='utf-8')
        for i in f.readlines():
            if i.rstrip():
                k, v = i.rstrip().split(': ', 2)
                if k == 'Content-Length':
                    continue
                self.headers[k.lower()] = v
        
        self.headers['cookie']=self.sessionId
        # log(self.headers)
        # print(self.headers['cookie'])
        # 读取key，ip，过期时间等
        # time.sleep(2)
     
        self.get_aes_key(self.headers['cookie'])
        # try:
        #     f = open('signature.txt', 'r', encoding='utf-8')
        #     self.key = str(f.read()).strip()
        # except:
        #     error('未获取到signature，尝试重启微信，并重启脚本')
        #     exit()
        # log('key', self.key)
        # 获取用户信息
        self.user = self.get_user()
        assert self.user
        log(self.user)

        # 获取医院信息，cid就是医院id
        # self.cid = self.get_cid()
        
        self.cid =self.config['zhimiao']['cid']
        assert self.cid
        # log('医院名称', self.config['zhimiao']['cname'])
        log('医院id', self.cid)

    # base64解密
    def base64_decrypt(self, ciphertext, charset='utf-8'):
        missing_padding = len(ciphertext) % 4
        if missing_padding:
            ciphertext += ('=' * (4 - missing_padding))
        result = base64.urlsafe_b64decode(ciphertext.encode(charset))
        # result = base64.b64decode(str(ciphertext))
        # log(result)
        return result

    # aes_cbc_128 加密
    def aes_encrypt(self, text, key, iv=b'1234567890000000', charset='utf-8'):
        def pkcs7_padding(data, block_size=128):
            if not isinstance(data, bytes):
                data = data.encode(charset)
            padder = padding.PKCS7(block_size).padder()
            return padder.update(data) + padder.finalize()

        cipher = AES.new(str(key).encode(charset), AES.MODE_CBC, iv)
        return b2a_hex(cipher.encrypt(pkcs7_padding(text))).decode()

    # aes_cbc_128 解密
    def aes_decrypt(self, ciphertext, key, iv=b'1234567890000000', charset='utf-8'):
        # print(key)
        try:
            json.loads(ciphertext)
            return ciphertext
        except Exception as e:
            pass

        def unpad(text):
            pad = ord(text[-1])
            return text[:-pad]

        cipher = AES.new(str(key).encode(charset), AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(a2b_hex(ciphertext)).decode(charset))

    # 根据cookie获取aes_key
    def get_aes_key(self, cookie, charset='utf-8'):
        assert (cookie.startswith('ASP.NET_SessionId='))
        cookie = cookie[len('ASP.NET_SessionId='):]
        # print("cookie",cookie)
        # 解析出jet payload
        result = self.base64_decrypt(cookie.split('.')[1])
        # log(result)
        self.exp = eval(result)['exp']
        exp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(eval(result)['exp']))
        # log('exp', exp)
        jwt = eval(str(result, charset))
        # jwt中有客户端ip 可能有限制
        # 解析出key和ip
        result = self.base64_decrypt(jwt['val'])
     
        # input()
        pattern = b'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)'
        ip = re.search(pattern, result).group(0)
        # log('ip', str(ip, charset))

    # md5加密
    def md5(self, t):
        m = hashlib.md5()
        m.update(t.encode('utf-8'))
        return m.hexdigest()

    # 发起get请求
    def get(self, url, proxies, wrong_time=0, data=None):
        time.sleep(self.interval)
        if time.time() >= self.exp:
            raise Exception('cookie 过期了')
        if wrong_time >= 10:
            raise Exception('get请求出错次数过多')
        try:
            # log(url)
            self.headers['zftsl'] = self.md5('zfsw_' + str(int(time.time() * 100)))
            res = self.session.get(
                url=url,
                headers=self.headers,
                params=data,
                timeout=1,
                proxies=proxies,
                verify=False
            )
            if proxies:
                log('proxies', proxies)
            if data:
                log('data', data)
            # log('res.text', res.text)
            return res
        except Exception as e:
            traceback.print_exc()
            if '出错次数过多' in str(e):
                raise e
            return self.get(url, proxies, wrong_time + 1, data=data)

    # 发起post请求
    def post(self, url, data, proxies, wrong_time=0):
        if time.time() >= self.exp:
            raise Exception('cookie 过期了')
        if wrong_time >= 10:
            raise Exception('post请求出错次数过多')
        try:
            log(url)
            if proxies:
                log('proxies', proxies)
            # log(data)
            log(json.dumps(data, separators=(',', ':'), ensure_ascii=False))
            params = self.aes_encrypt(json.dumps(data, separators=(',', ':'), ensure_ascii=False), self.key)
            # log(params)
            self.headers['zftsl'] = self.md5('zfsw_' + str(int(time.time() * 100)))
            res = self.session.post(
                url=url,
                headers=self.headers,
                data=params,
                timeout=1,
                proxies=proxies,
                verify=False
            )
            # print("状态",res.status_code)
            return res
        except Exception as e:
            error('post', e)
            if '出错次数过多' in str(e):
                raise e
            return self.post(url, data, proxies, wrong_time + 1)

    def run(self, max_times=30):
        # 等待时间到达
        self.t.start(0)
        log('1. 获取pid')
        w = 0
        while True:
            if w >= max_times:
                print('获取pid出错次数太多')
                exit()
            try:
                self.pid = self.get_pid()
                break
            except:
                traceback.print_exc()
                w += 1
        log('疫苗名称', self.config['zhimiao']['vaccines'])
        log('疫苗pid', self.pid)
        n = 0
        while True:
            log('第%d轮秒杀' % (n + 1))
            st = time.time()
            try:
                self.seckill()
            except Exception as e:
                # traceback.print_exc()
                if '过期了' in str(e):
                    exit()
            n += 1
            log('用时:', time.time() - st)
            if n >= max_times:
                error('抢购超时')
                break

    # 秒杀
    def seckill(self, max_times=30):
        # 获取预约日期
        dates = self.get_subscribe_dates()
        if(len(dates)==0):
                print("没有可预约的时间")
                return
        rdate = random.choice(dates)
        log('预约日期', rdate)
        try:
            # 获取预约时间
            times = self.get_subscribe_times(rdate)
       
            for i in range(len(times)):
                try:
                    rtime = times[i]
                    log('预约时间', '{}~{}'.format(rtime['StartTime'], rtime['EndTime']))
                    mxid = rtime['mxid']

                    # 识别验证码
                    # while True:
                    flag=self.get_captcha(mxid)
                        # if flag:
                        #     break

                    # 提交预约信息
                    data = {
                        'birthday': self.user['birthday'],
                        'tel': self.user['tel'],
                        'cname': self.user['cname'],
                        'sex': self.user['sex'],
                        'idcard': self.user['idcard'],
                        'doctype': self.user['doctype'],
                        'mxid': rtime['mxid'],
                        'date': rdate,
                        'pid': self.pid,
                        'Ftime': self.config['zhimiao']['Ftime'],  # 这个代表第几针
                        'guid': self.guid,
                    }
                    res = self.order_post(data)
                    print("提交预约信息",res.text)
                    log(res.text)
                    # print("开始下一轮2222")
                    if res.json()['status'] == 200:
                        while True:
                            log('6. 查询订单状态')
                            ww = 0
                            try:
                                # 查询订单状态
                                res = self.get_order_status()
                                log(res.text)
                                if res.json()['status'] == 200:
                                    log('抢购成功！！！')
                                    # exit()
                                    input()
                                    sys.exit()
                            except:
                                traceback.print_exc()
                                if ww >= max_times:
                                    error('应该被吞了 垃圾知苗')
                                    exit()
                                ww += 1
                    else:
                        raise Exception(res.text)
                        # print("开始下一轮")
                except Exception as e:
                    error(times[i], e)
                    if i == len(times) - 1:
                        raise e
        except Exception as e:
            self.config['zhimiao']['dates'].remove(rdate)
            raise e

    # 获取用户信息
    def get_user(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=User'
        return self.get(url,self.proxy).json()['user']

    # 获取医院id
    def get_cid(self):
        hospitals = []
        # 27是九价，28是四价
        for product in [27, 28]:
            url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerList&city=["{}","{}","{}"]&lat=&lng=&id=0&cityCode={}&product={}'.format(
                self.config['zhimiao']['province'],
                self.config['zhimiao']['city'],
                self.config['zhimiao']['county'],
                self.config['zhimiao']['cityCode'],
                product
            )
            res = self.get(url,self.proxy)
            hospitals.extend(res.json()['list'])
        for i in hospitals:
            if self.config['zhimiao']['cname'] in i['cname']:
                return i['id']
        raise Exception('未获取到医院信息')

    # 获取疫苗id
    def get_pid(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerProduct&id={}&lat=&lng='.format(
            self.cid
        )
        res = self.get(url,self.proxy)
        # print(res.json()['list'])
        for j in res.json()['list']:
            if self.config['zhimiao']['vaccines'] in j['text']:
            
                    if(j['id']!=""):
                        return j['id']

        raise Exception('未获取到疫苗信息')

    # 获取预约日期
    def get_subscribe_dates(self):
        log('2. 获取预约日期')
        if 'dates' not in self.config['zhimiao'] or not self.config['zhimiao']['dates']:
            url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCustSubscribeDateAll&pid={}&id={}&month={}'.format(
                self.pid, self.cid, datetime.datetime.now().strftime('%Y%m')
            )
            for i in range(10):
                res = self.get(url, self.proxy)
                if 'list' not in res.json() or not res.json()['list']:
                    time.sleep(self.interval)
                    continue
                dates = [i['date'] for i in res.json()['list'] if i['enable']]
                # dates = [i['date'] for i in res.json()['list']]
                self.config['zhimiao']['dates'] = dates
                return dates
            raise Exception('当前没有可预约的日期')
        else:
            return self.config['zhimiao']['dates']

    # 获取预约时间
    def get_subscribe_times(self, day):
        log('3. 获取预约时间')
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCustSubscribeDateDetail&pid={}&id={}&scdate={}'.format(
            self.pid, self.cid, day
        )
        for i in range(10):
            res = self.get(url, self.proxy)
            # res = self.get(url)
            if res.text.startswith('{') or res.text.startswith("<"):
                time.sleep(self.interval)
                continue
            ciphertext = res.text
            # log('ciphertext', ciphertext)
            # print("密钥",self.key)
            plaintext = self.aes_decrypt(ciphertext, self.key)
            log('解密', plaintext)
            times = [i for i in json.loads(plaintext)['list'] if i['qty']]
            if not times:
                # dates.remove(rdate)
                raise Exception('当前日期{}没有可预约的时间'.format(day))
            return times
        raise Exception('当前日期{}没有可预约的时间'.format(day))

    # 识别验证码
    def get_captcha(self, mxid):
        
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetCaptcha&mxid={}'.format(mxid)
        res = self.get(url, self.proxy)
        cd = requests.utils.dict_from_cookiejar(res.cookies)
        self.headers['cookie'] = '{}={}'.format('ASP.NET_SessionId', cd['ASP.NET_SessionId'])
        # res = self.get(url)
        # print("验证码",res.json())
        # print("验证码",res.text)
        if res.json()['status'] == 200:
            log('无验证码')
            # 更新cookie
            # log(self.headers['cookie'])

            return True
        if res.json()['status'] == 0:
            log('出现验证码')
            bg = res.json()['dragon'].replace(' ', '+')
            tp = res.json()['tiger'].replace(' ', '+')
            imgdata = base64.b64decode(bg)
            imgdata2 = base64.b64decode(tp)

            filename = 'bg.png'  # I assume you have a way of picking unique filenames
            filename2 = 'tp.png'  # I assume you have a way of picking unique filenames

            with open(filename, 'wb') as f:
                f.write(imgdata)
                f.close()
            with open(filename2, 'wb') as f:
                f.write(imgdata2)
                f.close()
            image1 = "./tp.png"

            image2 = "./bg.png"

            a=ty(image2,image1)
            # print("滑块移动",a)
            url2 = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CaptchaVerify&token=&x={}&y=5&mxid={}'.format(str(a),mxid)
            res2 = self.get(url2, self.proxy)
            # print("验证码链接",res2.headers)
            # print('验证码返回',res2.text)
            # print('验证码返回cookie',res2.cookies)
            plaintext = self.aes_decrypt(res2.text, self.key)
            # log('验证码返回', plaintext)
            p=json.loads(plaintext)
            if(p['status'] ==203):
                print("验证码错误，重新验证")
            if(p['status'] ==200):
                print("验证码成功")
                self.guid=p['guid']
                try:
                    cd2 = requests.utils.dict_from_cookiejar(res2.cookies)
                    self.headers['cookie'] = '{}={}'.format('ASP.NET_SessionId', cd2['ASP.NET_SessionId'])
                    return True
                except Exception as e:
                    print("验证码没有返回cookie")
        # else:
        #     log('4. 有验证码')
        #     with open('{}.txt'.format(int(time.time() * 1000)), 'w', encoding='utf-8') as f:
        #         f.write(res.text)
        #     raise Exception(res.text)

    # 提交订单
    def order_post(self, data):
        log('5. 提交订单')
        url = 'https://cloud.cn2030.com/sc/api/User/OrderPost'
        res = self.post(url, data, self.proxy)
        if res.json()['status'] != 200:
            # if res.json()['msg'] == '身份证不在预约范围.':
            #     error('order_post', res.text)
            #     exit()
            print(res.text)
            raise Exception(res.text)
        # 更新cookie
        # log(self.headers['cookie'])
        cd = requests.utils.dict_from_cookiejar(res.cookies)
        self.headers['cookie'] = '{}={}'.format('ASP.NET_SessionId', cd['ASP.NET_SessionId'])
        return res

    # 查询订单状态
    def get_order_status(self):
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=GetOrderStatus'
        res = self.get(url,self.proxy)
        print(res.text)
        if res.json()['status'] != 200:
            raise Exception(res.text)
        return res






def getProxy():
    
    targetUrl = "http://api.xiequ.cn/VAD/GetIp.aspx?act=get&uid=101534&vkey=185D2A6F9C5B16CDF7B11E7C429F8467&num=1&time=30&plat=1&re=1&type=0&so=1&ow=1&spl=1&addr=广东&db=1"
    resp=requests.get(targetUrl)

    print(resp.text.split("\r\n"))
    return resp.text.split("\r\n")

def dq(ip,strip):
    
    url = "https://sp1.baidu.com/8aQDcjqpAAV3otqbppnN2DJv/api.php?query="+str(ip)+"&resource_id=5809"

    payload={}


    response = requests.request("GET", url, data=payload)
    print(response.json()['data'][0]['location'])
    print(response.json()['data'][0]['location'].find(strip))
    if(response.json()['data'][0]['location'].find(strip)!=-1):
        return True
    else:
        return False
    


def getcode(code,proxys):
    

    url = "https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=auth&code="+str(code)

    payload={
           "rawdata" : "{\"nickName\":\"微信用户\",\"gender\":0,\"language\":\"\",\"city\":\"\",\"province\":\"\",\"country\":\"\",\"avatarUrl\":\"https://thirdwx.qlogo.cn/mmopen/vi_32/POgEwh4mIHO4nibH0KlMECNjjGxQUq24ZEaGT4poC6icRiccVGKSyXwibcPq4BWmiaIGuG1icwxaQX6grC9VemZoJ8rg/132\"}"

    }
    
    headers = {
    'Host': 'cloud.cn2030.com',
    'Connection': 'keep-alive',
    'charset': 'utf-8',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; M2006J10C Build/SP1A.210812.016; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/86.0.4240.99 XWEB/4343 MMWEBSDK/20220805 Mobile Safari/537.36 MMWEBID/3972 MicroMessenger/8.0.27.2220(0x28001B37) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android',
    'content-type': 'application/json',
    'Accept-Encoding': 'gzip,compress,br,deflate',
    'Referer': 'https://servicewechat.com/wx2c7f0f3c30d99445/95/page-frame.html'
    }

    response = requests.request("POST", url, headers=headers, json=payload,proxies=proxys,verify=False)
    print(response.json())
    if(response.json()['status']==200):
        sessionId=response.json()['sessionId']
        print("获取cookie成功")
        return sessionId
    else:
        print("获取sessionId出错")
        exit()



def ty(bg,tp):

    # path=''
    # image=cv2.imread(path)
    # image=cv2.cvtColor(image,cv2.COLOR_RGB2GRAY)
    # ret,binary=cv2.threshold(image,250,250,cv2.THRESH_BINARY )
    # def identify_gap(bg="./bg.png", tp="./tp.png"):
    bg_img = cv2.imread(bg)  # 背景图片
    tp_img = cv2.imread(tp)  # 缺口图片
    # bg_edge = cv2.Canny(bg_img, 310, 155)
    # tp_edge = cv2.Canny(tp_img, 47, 155)
    # bg_pic = cv2.cvtColor(bg_edge, cv2.COLOR_GRAY2RGB)
    bg_pic=cv2.cvtColor(bg_img,cv2.COLOR_RGB2GRAY)
    tp_pic = cv2.cvtColor(tp_img, cv2.COLOR_RGB2GRAY)
    ret,binary=cv2.threshold(bg_pic,250,250,cv2.THRESH_BINARY )
    # cv2.imshow('THRESH_BINRY',binary)
    # cv2.waitKey(0)
    # cv2.destroyAllWindows()

    res = cv2.matchTemplate(binary, tp_pic, cv2.TM_CCOEFF_NORMED)
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(res)  # 寻找最优匹配
    th, tw = tp_pic.shape[:2]
    tl = max_loc
    br = (tl[0] + tw, tl[1] + th)  # 右下角点的坐标
    cv2.rectangle(bg_img, tl, br, (16, 16, 255), 3)  # 绘制矩形
    # print(f"X的值: {tl[0]}\n")
    return tl[0]


def findyy(dz,yy):
    with open('city.txt','r') as file:
        content=file.read()
    city=content.rstrip().split("\n")
    flag=False
    for i in range(0,len(city)):
        # print(city[i].find(str(dz)))
        if(city[i].find(str(dz))!=-1):
            flag=True
            lng=city[i].split("-")[1]
            lat=city[i].split("-")[2]
            print(dz+"lng",city[i].split("-")[1])
            print(dz+"lat",city[i].split("-")[2])
            
            url = "https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerList&city=[\"\",\"\",\"\"]&lat="+str(lat)+"&lng="+str(lng)+"&id=0&cityCode=0&product=0"

            payload={}
            headers = {
            'Referer': 'https://servicewechat.com/wx2c7f0f3c30d99445/95/page-frame.html',
            'Cookie': 'ASP.NET_SessionId=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2Njc2OTYzNTkuODg0ODk1NiwiZXhwIjoxNjY3Njk5OTU5Ljg4NDg5NTYsInN1YiI6IllOVy5WSVAiLCJqdGkiOiIyMDIyMTEwNjA4NTkxOSIsInZhbCI6IjJLN0ZBQUlBQUFBRWFHRm9ZUnh2Y1hJMWJ6VkRVRmRuYmxCak4xaFBhRTVNWDA0M2FscHdOVFZKQVJ4dlZUSTJXSFI1UkhJMGExZDRcclxuWlZKVldsSnFNbFE0V1UwNVdtbHJEREl5TVM0M0xqZ3lMakl6TkFBQUFBQUFBQUE9In0.HsXUq_T8EVgWxkdH9-2134eA5k8PSLcp6EjTJ0qbnRU'
            }

            response = requests.get( url, headers=headers, data=payload,verify=False)
            # print(response.text)
            yylist=response.json()['list']
            yylist2=[]
            for i in range(len(yylist)):
                if(yylist[i]['cname'].find(str(yy))!=-1):
                    
                    ob={
                        "id":yylist[i]['id'],
                        "cname":yylist[i]['cname']
                    }
                    yylist2.append(ob)
            if(len(yylist2)==0):
                print("没有找到该医院")
                exit()
            if(len(yylist2)==1):
                print(ob)
                return [yylist2[0]['id'],yylist2[0]['cname']]
            else:
                for i in range(0,len(yylist2)):
                    print(str(i)+"   "+str(yylist2[i]['id'])+"   "+yylist2[i]['cname'])
                a=input("输入要序号：")
                return [yylist2[int(a)]['id'],yylist2[int(a)]['cname']]
                # exit()
    if(flag==False):
        print("没有找到该地区")
        exit()
        
def file_config():  # 初始化配置文件

    cf = configparser.RawConfigParser()

    if (os.path.exists('config.ini')):
        pass
    else:
        print("初始化配置文件")
        cf["config"] = {'starttime': "2022-12-03 09:00:00.000",
                      'sessionid': 0,
                     'signature': 0,
                     'cid': 0,
                     'cname': 0,
                     'vaccines': 0
                
                     }	
  
        with open('config.ini', 'w',encoding='gb2312') as configfile:

            cf.write(configfile)
        print('请先配置')
        sys.exit(0)        
def findvc(cid):
        header = {
    'Host': 'cloud.cn2030.com',
    'Connection': 'keep-alive',
    'charset': 'utf-8',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 12; M2006J10C Build/SP1A.210812.016; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/86.0.4240.99 XWEB/4343 MMWEBSDK/20220805 Mobile Safari/537.36 MMWEBID/3972 MicroMessenger/8.0.27.2220(0x28001B37) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android',
    'content-type': 'application/json',
    'Accept-Encoding': 'gzip,compress,br,deflate',
    'Referer': 'https://servicewechat.com/wx2c7f0f3c30d99445/95/page-frame.html'
    }
        url = 'https://cloud.cn2030.com/sc/wx/HandlerSubscribe.ashx?act=CustomerProduct&id='+str(cid)+'&lat=&lng='
        res = requests.get(url,headers=header,verify=False)
        # print(res.json())
        i=0
        for j in res.json()['list']:
                # if self.config['zhimiao']['vaccines'] in j['text']:
                print(str(i)+"  "+j['text']+"  "+j['BtnLable'])
                i=i+1
        a=input("请选择：")
        
        return res.json()['list'][int(a)]['text']
if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__))
     
    i=os.system("cls")
    file_config()
    config = configparser.ConfigParser()
    config.read('config.ini',encoding='gb2312')
    signature=config.get('config', 'signature')
    sessionId=config.get('config', 'sessionId')
    startTime=config.get('config', 'startTime')
    vaccines=config.get('config', 'vaccines')
    cname=config.get('config', 'cname')
    cid=config.get('config', 'cid')
    print("1.重新配置")
    print("2.上次配置")
    print("3.代理模式")
    mode=input("输入mode:")
    if(mode=="1"):
        os.system("cls")
        city=input("输入城市：")
        yy=input("输入医院：")
        xx=findyy(city,yy)
        vaccines=findvc(xx[0])
        print("cid",str(xx[0]))
        print("vaccines",vaccines)
        print("cname",str(xx[1]))
        config.set('config', 'cid', str(xx[0]))# 给type分组设置值
        config.set('config', 'vaccines', str(vaccines))# 给type分组设置值
        config.set('config', 'cname', str(xx[1]))# 给type分组设置值

        o = open('config.ini', 'w',encoding='gb2312')
        config.write(o)
        o.close()#不要忘记关闭
        proxies=None
        code=input("输入code:")
        sessionId=getcode(code,proxies)
        signature=input("输入signature:")
        config.set('config', 'sessionId', sessionId)# 给type分组设置值
        config.set('config', 'signature', signature)# 给type分组设置值
        o = open('config.ini', 'w')
        config.write(o)
        o.close()#不要忘记关闭
        config2 = {
        # 知苗配置
                "zhimiao": {


            "vaccines": vaccines,
            "cname": xx[1],
             "Ftime":1,
            # 抢购开始时间
            "startTime": startTime,
            "cid":xx[0]
        }
    }
        z = ZmyySeckill(config2,signature,sessionId, proxy=proxies)
        z.run()

    if(mode=="2"):
        os.system("cls")
        print("cid",cid)
        print("vaccines",vaccines)
        print("cname",cname)
        bb = {
        # 知苗配置
                "zhimiao": {


            "vaccines": vaccines,
            "Ftime":1,
            # 抢购开始时间
            "startTime": startTime,
            "cid":cid
        }
    }
        proxies=None
        z = ZmyySeckill(bb,signature,sessionId, proxy=proxies)
        z.run()
    if(mode=="3"):
        while True:
            ip=getProxy()
            if(dq(ip[0],"广东省")):
                break
        proxies = {           'http':'http://'+ip[0], 
               'https':'http://'+ip[0]  }
        print(proxies)
        code=input("输入code:")
        sessionId=getcode(code,proxies)
        signature=input("输入signature:")
        config.set('config', 'sessionId', sessionId)# 给type分组设置值
        config.set('config', 'signature', signature)# 给type分组设置值
        o = open('config.ini', 'w')
        config.write(o)
        o.close()#不要忘记关闭
        z = ZmyySeckill(config2,signature,sessionId, proxy=proxies)
        z.run()
    
    # if os.path.exists('signature.txt'):
    #     os.remove('signature.txt')
    # # 启动hook线程
    # t = threading.Thread(target=hook)
    # t.start()
    # # 启动抓包线程
    # t1 = threading.Thread(target=capture)
    # t1.start()
    # t1.join()
    # z = ZmyySeckill(config2)
    # z.run()
