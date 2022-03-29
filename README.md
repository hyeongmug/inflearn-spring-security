### 강의 주소
https://www.inflearn.com/course/백기선-스프링-시큐리티

## 학습 정리
### 3강 - 스프링 시큐리티 연동
pom.xml 등록
``` xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 4강 - 스프링 시큐리티 설정하기
SecurityConfig 클래스를 생성
``` java
@Configuration
@EnableWebSecurity
public class SecurityConifg extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated();
        http.formLogin();
        http.httpBasic();
    }
}
```
- WebSecurityConfigurerAdapter 를 상속 받는다.
- @Configuration 어노테이션 @EnableWebSecurity 어노테이션 필요하다.

요청 URL 별로 인증하는 방법

1. nfigure(HttpSecurity http) 오버라이드
2. 요청 승인을 위한 http.authorizeRequests() 호출
3. mvcMatchers 또는  anyRequest 을 사용해서 요청을 구분할 수 있다.
    - .mvcMatchers("/", "/info") : url 패턴을 등록
    - .anyRequest() : mvcMatchers 요청을 제외한 모든 요청
    - 하위 메소드
        - .permitAll() : 접근을 모두 허용
        - .hasRole("ADMIN") : 인증이 필요, ADMIN 권한만 허용
        - .authenticated() : 인증 필요

### 5강 - 인메모리 유저 추가
하드하게 유저 정보를 추가하는 방법으로는 properties를 사용한 방법과 시큐리티 설정을 이용하는 방법이 있다.

#### properties를 사용하는 방법
``` properties
spring.security.user.name=admin
spring.security.user.password=123
spring.security.user.roles=ADMIN
```  

#### 시큐리티 설정에 추가하는 방법
1. SecurityConfig 에서 AuthenticationManagerBuilder auth를 제공하는 configure메소드를 오버라이드 한다.
2. auth.inMemoryAuthentication() 호출
    - 하위 메소드로 withUser(), password(), role() 을 사용하여 유저 정보를 추가 할 수있다.
``` java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("keesun").password("{noop}123").roles("USER").and()
        .withUser("admin").password("{noop}!@#").roles("ADMIN");
}
```
- {}안에 암호화 방법을 적는다.
    - noop은 스프링부트 기본 패스워드 인코더
        - 비밀번호 앞에 {noop} 프리픽스가 있으면 noop으로 패스워드를 인코딩 한다.

### 6강 - JPA 연동 / UserDetailService 구현
1. pom.xml 에 jpa, h2 추가
``` xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>runtime</scope>
</dependency>
```
3. Account 클래스, AccountRepository 클래스 추가 - 본 문서는 시큐리티 설명이 메인이므로 JPA 관련된 자세한 소스는 생략
4. UserDetailsService 인터페이스를 구현하는 AccountService 클래스 생성
``` java
@Service
public class AccountService implements UserDetailsService {

    @Autowired AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);
        if (account == null) {
            throw new UsernameNotFoundException(username);
        }

        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }
}
```
- UserDetailsService : DAO를 사용해서 유저정보를 가져와서 인증할 때 사용되는 인터페이스, 즉 데이터베이스에서 유저 정보를 가져와서 인증할 때 사용된다.
- loadByUsername 메소드
    - username을 받아서 username에 해당하는 유저 정보를 DB에서 가져와서 UserDetails 타입(인터페이스 타입)으로 리턴하는 역할 수행
    - 스프링 시큐리티에서 제공하는 User 클래스를 사요하면 UserDetails로 쉽게 변환 할 수 있다.

### 7강 - PasswordEncoder
``` java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```
- PasswordEncoder는 스프링 시큐리티가 권장하는 방법이며, 다양한 암호화 알고리즘을 지원한다.
    - {id}를 사용하면 특정 포맷으로 암호화 한다.
    - ex) `passwordEncoder.encode("{sha256}비밀번호")`
- PasswordEncoder는 기본 전략이 예전에 NoOp을 사용했고 지금은 BCrypt를 사용한다.
    - 스프링 시큐리티 5.0 부터 BCrypt를 사용
    - ex) `passwordEncoder.encode("비밀번호")` -> 기본이 BCrypt 이므로 BCrypt로 암호화 된다.

### 8강, 9강 - 스프링 시큐리티 테스트
1. pom.xml 에 spring-security-test 추가
``` xml 
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
    <version>${spring-security.version}</version>
</dependency>
```
2. MockMvc를 사용해서 권한이 부여된 테스트 유저를 만들어서 특정한 URI로 접속했을 때 접근이 허용되는지 테스트를 할 수 있다.
     - with() 메소드를 사용한 방법
        <details>
        <summary>소스 보기</summary>
        <div markdown="1">

        ``` java
        @RunWith(SpringRunner.class)
        @SpringBootTest
        @AutoConfigureMockMvc
        public class AccountControllerTest {
            @Autowired
            MockMvc mockMvc;
    
            @Test
            public void index_anonymous() throws Exception {
            mockMvc.perform(get("/").with(anonymous()))
                    .andDo(print())
                    .andExpect(status().isOk());
            }
    
            @Test
            public void index_user() throws Exception {
                mockMvc.perform(get("/").with(user("keesun").roles("USER")))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
    
            @Test
            public void admin_user() throws Exception {
                mockMvc.perform(get("/").with(user("keesun").roles("USER")))
                        .andDo(print())
                        .andExpect(status().isForbidden());
            }
    
            @Test
            public void admin_admin() throws Exception {
                mockMvc.perform(get("/admin").with(user("keesun").roles("ADMIN")))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
        }
        ```
        </div>
        </details>

    - 어노테이션을 사용한 방법
        <details>
        <summary>소스 보기</summary>
        <div markdown="1">

        ``` java
        @RunWith(SpringRunner.class)
        @SpringBootTest
        @AutoConfigureMockMvc
        public class AccountControllerTest {
        @Autowired
        MockMvc mockMvc;
    
            @Test
            @WithAnonymousUser
            public void index_anonymous() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
    
            @Test
            @WithMockUser(username = "keesun", roles = "USER")
            public void index_user() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
    
            @Test
            @WithMockUser(username = "keesun", roles = "USER")
            public void admin_user() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isForbidden());
            }
    
            @Test
            @WithMockUser(username = "keesun", roles = "ADMIN")
            public void admin_admin() throws Exception {
                mockMvc.perform(get("/admin"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
        }
        ```
        </div>
        </details>

    - 커스컴 어노테이션을 만들어서 사용하기
        <details>
        <summary>소스 보기</summary>
        <div markdown="1">

        ``` java
        @Retention(RetentionPolicy.RUNTIME)
        @WithMockUser(username = "keesun", roles = "USER")
        public @interface WithUser {

        }
        ```

        ``` java
        @RunWith(SpringRunner.class)
        @SpringBootTest
        @AutoConfigureMockMvc
        public class AccountControllerTest {
            @Autowired
            MockMvc mockMvc;

            @Test
            @WithAnonymousUser
            public void index_anonymous() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }

            @Test
            @WithUser
            public void index_user() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }

            @Test
            @WithUser
            public void admin_user() throws Exception {
                mockMvc.perform(get("/"))
                        .andDo(print())
                        .andExpect(status().isForbidden());
            }

            @Test
            @WithMockUser(username = "keesun", roles = "ADMIN")
            public void admin_admin() throws Exception {
                mockMvc.perform(get("/admin"))
                        .andDo(print())
                        .andExpect(status().isOk());
            }
        }
        ```
        </div>
        </details>
3. MockMvc를 사용해서 폼(로그인 폼 화면)으로 로그인 하는 경우를 테스트 할 수 있다.
   - formLogin() 을 사용한다.
        
       <details>
       <summary>소스 보기</summary>
       <div markdown="1">
    
       ``` java
       @Test
       @Transactional
       public void login_success() throws Exception {
           String username = "keesun";
           String password = "123";
           Account user = this.createUser(username, password);
           mockMvc.perform(formLogin().user(user.getUsername()).password(password))
                   .andExpect(authenticated());
       }
    
       @Test
       @Transactional
       public void login_fail() throws Exception {
           String username = "keesun";
           String password = "123";
           Account user = this.createUser(username, password);
           mockMvc.perform(formLogin().user(user.getUsername()).password("12345"))
                   .andExpect(authenticated());
       }
    
       private Account createUser(String username, String password) {
           Account account = new Account();
           account.setUsername(username);
           account.setPassword(password);
           account.setRole("USER");
           return  accountService.createNew(account);
       }
       ```
       </div>
       </details>
   
### 10강 - SecurityContextHolder와 Authentication
#### SecurityContextHolder 구조

![img_3.png](img_3.png)

#### SecurityContextHolder
- SecurityContextHolder는 SecurityContext를 제공해 준다.
  - SecurityContext을 제공하는 기본적인 방법으로 ThreadLocal(한 쓰레드 내에서 공유하는 저장소)을 사용한다.

#### SecurityContext
- Authentication을 제공한다.

#### Authentication
- Principal과 GrantAuthority를 제공한다.

#### Principal 
- 인증된 사용자 정보를 나타낸다.
  - UserDetailsService에서 리턴한 **UserDetails 타입**의 객체이다.
  - 최종적으로는 UserDetails 구현체인 **User 타입**
- Principal은 Authentication 안에 담겨져 있다.

#### GrantAuthority
- Principal이 가지고 있는 "권한"을 나타낸다.
  - "ROLE_USER", "ROLE_ADMIN" 등
- 인증이 된 이후에 **인가와 권한**을 확인 하기 위해 사용된다.

#### Credentials
- 자격 증명을 나타냅니다. 예를 들면 password가 될 수 있습니다.

#### UserDetails 
- 애플리케이션이 가지고 있는 유저 정보와 스프링 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.

#### UserDetailService
- 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스
- 구현은 마음대로 할 수 있다. 
- **UserDetails를 리턴 한다.**

#### 실습 코드
디버거를 사용해서 정보가 무엇 무엇이 있는지 확인해 본다.
``` java
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
Object principal = authentication.getPrincipal();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
Object credentials = authentication.getCredentials();
boolean authenticated = authentication.isAuthenticated();
```

코드는 SecurityContextContext 하나만 기억하고 있으면 점을 찍어서 자동완성으로 쉽게 작성할 수 있다.
 
![img.png](img.png)
 
![img_2.png](img_2.png)

![img_1.png](img_1.png)

### 12강 - AuthenticationManager와 Authentication
인증이 어떻게 이루어지고, 그 인증이 이루어지는 과정에 어떠한 일들이 벌어질수 있는지를 살펴본다.
#### AuthenticationManager 인터페이스
- 실제로 Authentication 을 만들고 인증을 처리한다.
- AuthenticationManager에는 authenticate 메서드 하나만 존재한다.
    ``` java
      Authentication authenticate(Authentication authentication) throws AuthenticationException;
    ```
  - authenticate 메소드에서 인자로 받는 authentication과 리턴하는 authentication의 차이
    - 인자로 받은 authentication 객체의 인증 정보가 유효하면 실제로 인증 처리된 authentication 객체를 리턴한다.
    - 실제로 인증된 authentication은 UserDetailsService가 리턴한 UserDetails 객체, 즉 principal 객체를 담고 있다.  
    - **인자 authentication**
      - ![img_4.png](img_4.png)
    - **리턴 authentication**
      - ![img_5.png](img_5.png)

- 기본 구현체는 ProviderManager 이다.
- ProviderManager 로 인증이 되는 과정
  - ProviderManager ==> 다른 Provider에 위임 ==> DaoAuthenticationProvider 에서 UserDetailsService의 loadUserByUsername 메서드를 호출한다.

### 12강 - ThreadLocal
- java.lang 패키지에서 기본적으로 제공하는 기능
- 쓰레드 범위 내에서 사용하는 변수
``` java
public class AccountContext {

    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }

    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}
```
- SecurityContextHolder 에서 getContext()로 SecurityContext를 꺼내오는 것과 같은 방법이다.

