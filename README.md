# [백기선] 인프런 스프링 시큐리티
- 강의 주소 https://www.inflearn.com/course/백기선-스프링-시큐리티
## 목차
- [[백기선] 인프런 스프링 시큐리티](#백기선-인프런-스프링-시큐리티)
    * [목차](#--)
    * [학습 정리](#-----)
        + [3강 - 스프링 시큐리티 연동](#3강---스프링-시큐리티-연동)
        + [4강 - 스프링 시큐리티 설정하기](#4강---스프링-시큐리티-설정하기)
        + [5강 - 인메모리 유저 추가](#5강---인메모리-유저-추가)
            - [properties를 사용하는 방법](#properties를-사용하는-방법)
            - [시큐리티 설정에 추가하는 방법](#시큐리티-설정에-추가하는-방법)
        + [6강 - JPA 연동 / UserDetailService 구현](#6강---jpa-연동--userdetailservice-구현)
        + [7강 - PasswordEncoder](#7강---passwordencoder)
        + [8강, 9강 - 스프링 시큐리티 테스트](#8강-9강---스프링-시큐리티-테스트)
        + [10강 - SecurityContextHolder와 Authentication](#10강---securitycontextholder와-authentication)
            - [SecurityContextHolder 구조](#securitycontextholder-구조)
            - [SecurityContextHolder](#securitycontextholder)
            - [SecurityContext](#securitycontext)
            - [Authentication](#authentication)
            - [Principal](#principal)
            - [GrantAuthority](#grantauthority)
            - [Credentials](#credentials)
            - [UserDetails](#userdetails)
            - [UserDetailService](#userdetailservice)
            - [실습 코드](#실습-코드)
        + [12강 - AuthenticationManager와 Authentication](#12강---authenticationmanager와-authentication)
            - [AuthenticationManager 인터페이스](#authenticationmanager-인터페이스)
        + [12강 - ThreadLocal](#delegatingfilterproxy)
        + [13강 - Authentication과 AuthenticationManager](#13강---authentication과-authenticationmanager)
            - [처리 순서](#처리-순서)
        + [14강 - 시큐리티 Filter와 FilterChainProxy](#14강---시큐리티-filter와-filterchainproxy)
            - [스프링 시큐리티가 제공하는 15개의 필터들](#스프링-시큐리티가-제공하는-15개의-필터들)
        + [15강 - DelegatingFilterProxy와 FilterChainProxy](#15강---delegatingfilterproxy와-filterchainproxy)
            - [DelegatingFilterProxy](#delegatingfilterproxy)
        + [16강 - AccessDecisionManager](#16----accessdecisionmanager)
            - [AccessDecisionManager](#accessdecisionmanager)
            - [AccessDecisionVoter](#accessdecisionvoter)
        + [17강 - RoleHierarchy로 계층형 ROLE 설정 방법](#17강---rolehierarchy로-계층형-role-설정-방법)
        + [18강 - FilterSecurityInterceptor](#18강---filtersecurityinterceptor)
            - [FilterSecurityInterceptor](#filtersecurityinterceptor)
        + [중간 정리(12강 ~ 18강)](#중간-정리12강--18강)
            - [인증과 인가 처리의 과정 요약](#인증과-인가-처리의-과정-요약)
        + [19강 - ExceptionTranslationFilter](#19강---exceptiontranslationfilter)
        + [20강 - 스프링 시큐리티 아키텍처 정리](#20강---스프링-시큐리티-아키텍처-정리)
        + [21강 - 스프링 시큐리티 ignoring() 1부](#21강---스프링-시큐리티-ignoring-1부)
        + [22강 - 스프링 시큐리티 ignoring() 2부](#22강---스프링-시큐리티-ignoring-2부)
        + [23강 - Async 웹 MVC를 지원하는 필터: WebAsyncManagerIntegrationFilter](#23강---async-웹-mvc를-지원하는-필터-webasyncmanagerintegrationfilter)
        + [24강 - 스프링 시큐리티와 @Async](#24강---스프링-시큐리티와-async)
            - [@Async 사용하기](#async-사용하기)
            - [@Async 사용과 principal 공유](#async-사용과-principal-공유)
        + [25강 - SpringSecurity 영속화 필터: SecurityContextPersistenceFilter](#25강---springsecurity-영속화-필터-securitycontextpersistencefilter)
        + [26강 - 시큐리티 관련 헤더 추가하는 필터: HeaderWriterFilter](#26강---시큐리티-관련-헤더-추가하는-필터-headerwriterfilter)
        + [27강 - CSRF 어택 방지 필터: CsrfFilter](#27강---csrf-어택-방지-필터-csrffilter)
            - [CSRF](#csrf)
            - [CsrfFilter](#csrffilter)
        + [28강 - CSRF 토큰 사용 예제](#28강---csrf-토큰-사용-예제)
        + [29강 - 로그아웃 처리 필터: LogoutFilter](#29강---로그아웃-처리-필터-logoutfilter)
            - [LogoutFilter 설정 방법](#logoutfilter-설정-방법)
        + [30강. 폼 로그인을 처리하는 인증 필터: UsernamePasswordAuthenticationFilter](#30강-폼-로그인을-처리하는-인증-필터-usernamepasswordauthenticationfilter)
        + [31강 - DefaultLoginPageGeneratingFilter](#31강---defaultloginpagegeneratingfilter)
            - [기본 로그인 화면](#기본-로그인-화면)
        + [32강 - 로그인 / 로그아웃 폼 커스터마이징](#32강---로그인--로그아웃-폼-커스터마이징)
            - [SecurityConfig.java](#securityconfigjava)
            - [LogInOutController.java](#loginoutcontrollerjava)
            - [login.html](#loginhtml)
            - [logout.html](#logouthtml)


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
- @Configuration 어노테이션 @EnableWebSecurity 어노테이션을 추가한다.
- @EnableWebSecurity은 없어도 스프링 부트 자동설정이 자동으로 추가해준다.

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
        <div>

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
        <div>

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
        <div>

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
       <div>
    
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

![img_3.png](assets/img_3.png)

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
 
![img.png](assets/img.png)
 
![img_2.png](assets/img_2.png)

![img_1.png](assets/img_1.png)

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
      - ![img_4.png](assets/img_4.png)
    - **리턴 authentication**
      - ![img_5.png](assets/img_5.png)

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

### 13강 - Authentication과 AuthenticationManager
AuthenticationManager를 통해서 인증을 마친 Authentication 객체가 언제 SecurityContextHolder 안으로 들어가는지 살펴본다.
- 크게 두가지의 Filter가 SecurityContextHolder에 Authentication 객체를 넣어준다.
  - **UsernamePasswordAuthenticationFilter**
    - 폼인증을 처리하는 시큐리티 필터이다. 
    - 인증된 Authentication객체를 SecurityContextHolder에 넣어준다.
  - **SecurityContextPersistenceFilter**
    - SecurityContext를 HTTP session에 캐시(기본 전략)하여 여러 요청에서 Authentication을 공유할 수 있도록 공유하는 필터이다.
    - 여러 요청시에도 **인증한 유저는 동일한 Authentication**을 갖을 수 있게 해준다.

#### 처리 순서
1. 요청이 이루어 진다.
2. SecurityContextPersisenceFilter는 캐싱하고 있는 SecurityContext를 읽어온다. 
3. 읽어온 SecurityContext을 SecurityCotextHolder에 넣는다.
4. UsernamePasswordAuthenticationFilter로 체인되어 인증이 이루어진다.
5. 인증이 성공하면 UsernamePasswordAuthenticationFilter의 부모 클래스인 AbstractAuthenticationProcessingFilter에 있는 successfulAuthentication 메소드가 실행 된다.
6. successfulAuthentication 메소드에서 최종적으로 authentication가 set된다.
    ``` java
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authResult);
    SecurityContextHolder.setContext(context);
    ```
   
### 14강 - 시큐리티 Filter와 FilterChainProxy
#### 스프링 시큐리티가 제공하는 15개의 필터들
1. WebAsyncManagerIntegrationFilter
2. SecurityContextPersistenceFilter
3. HeaderWriteFilter
4. CsrfFilter
5. LogoutFilter
6. UsernamePasswordAuthenticationFilter
7. DefaultLoginPageGeneratingFilter
8. DefaultLogoutPageGeneratingFilter
9. BasicAuthenticationFilter
10. RequestCacheAwareFilter
11. SecurityContextHolderAwareRequestFilter
12. AnonymousAuthenticationFilter
13. SessionManagementFilter
14. ExceptionTranslationFilter
15. FilterSecurityInterceptor

- **FilterChainProxy**에서 위 필터들을 순차적으로 실행 시킨다.
- SecurityConfig 는 여러개 만들수 있으며 SecurityConfig 하나가 하나의 체인이다.
- 실행할 필터들의 목록이 만들어지는 곳은 SecurityConfig이다.
- SecurityConfig에서의 설정에 따라서 필터 갯수가 달라진다.

``` java
protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/account/**")
            .authorizeRequests()
            .anyRequest().permitAll();
}
```
- 필터 갯수가 12개이다.

``` java
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .mvcMatchers("/", "/info", "/account/**").permitAll()
        .mvcMatchers("/admin").hasRole("ADMIN")
        .anyRequest().authenticated();
    http.formLogin();
    http.httpBasic();
}
```
- 필터 갯수가 15개이다.

### 15강 - DelegatingFilterProxy와 FilterChainProxy
요청을 했을 때 어떻게 FilterChainProxy 까지 들어가지는지 알아본다.

#### DelegatingFilterProxy
- 이름에서 암시하듯 자기가 처리를 하지 않고 다른 빈에게 위임을 하고 싶을 때 사용하는 서블릿 필터이다.
- 위임하기 위해서는 위임하려는 빈의 이름을 지정 해줘야된다.

FilterChainProxy은 DelegatingFilterProxy을 통해서 위임된다.
- AbstractSecurityWebApplicationInitializer 에서 'springSecurityFilterChain' 이라는 이름으로 위임된다.
``` java
String filterName = "springSecurityFilterChain";
DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy(filterName);
```

### 16강 - AccessDecisionManager
지금까지는 인증(Authentication)을 다루는 부분을 쭉 살펴봤다면, 이제부터는 허가 (Access Control 또는 Authorization)을 다루는 인터페이스를 중심으로 살펴본다.
#### AccessDecisionManager
- 이미 인증을 거친 사용자가 특정한 서버의 리소스에 접근을 하려고 할 때 그것을 허용할 것인가, 그게 유용한 요청인가를 판단하는 인터페이스 이다.
- Access Control 결정을 내리는 인터페이스로, 구현체 3가지를 기본으로 제공한다.
  - **AffirmativeBased**: 여러 Voter 중에 한명이라도 허용하면 허용한다. (기본 구현체) 
    - 허용하지 않으면 Exception이 발생한다.
  - ConsensusBased: 다수결 (사용하는 경우가 흔하지 않다)
  - UnanimousBased: 만장일치
#### AccessDecisionVoter
  - 해당 Authentication이 특정한 Object에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인한다.
      - 위에서 말한 특정한 Object라 함은 접근하려는 대상인 mvcMatchers("/admin") 등을 말하고
      - ConfigAttributes는 permitAll(), hasRole("xxx") 등을 말한다.
  - **WebExpressionVoter**
    - 웹 시큐리티에서 사용하는 기본 구현체이다.
    - ROLE_Xxxx가 매치하는지 확인한다.
  - RoleHierarchyVoter
    - 계층형 ROLE을 지원한다.
    - ex) ADMIN > MANAGER > USER

### 17강 - RoleHierarchy로 계층형 ROLE 설정 방법
``` java
public SecurityExpressionHandler expressionHandler() {
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
    roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

    DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
    handler.setRoleHierarchy(roleHierarchy);

    return handler;
}

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .mvcMatchers("/", "/info", "/account/**").permitAll()
            .mvcMatchers("/admin").hasRole("ADMIN")
            .mvcMatchers("/user").hasRole("USER")
            .anyRequest().authenticated()
            .expressionHandler(expressionHandler());
    http.formLogin();
    http.httpBasic();
}
```

### 18강 - FilterSecurityInterceptor
AccessDecisionManager가 어디서 사용하고 있는지 알아본다.
#### FilterSecurityInterceptor
- AccessDecisionManager를 사용하여 Access Control 또는 예외 처리를 하는 필터이다.
- 대부분의 경우 FilterChainProxy의 제일 마지막 필터로 들어있다.

### 중간 정리(12강 ~ 18강)
#### 인증과 인가 처리의 과정 요약
- `ScurityContextHolder`가 `Authentication`을 가지고 있다.
- `Authentication`은 `AuthenticationManager`를 통해서 인증을 한다.
- 결과로 나온 `Authentication`을 다시 `SecurityContextHolder`에 넣어준다.
- 그런 역할을 하는게 `UsernamePasswordAuthenticationFilter`이다.
- 그런 다음에 `SecurityContextPersistenceFilter`에서도 한다.
- 이런 필터들은 `FilterChainProxy`를 통해서 묶여 있다.
- `FilterChainProxy`가 팔터들을 일일이 순차적으로 실행을 해준다.
- 그런데 이 `FilterChainProxy`도 사실상 `DelegatingFilterProxy`를 통해서 요청을 전달 받은 것이다.
- `DelegatingFilterProxy`는 스프링 부트를 사용할 떄는 자동으로 등록 되기 때문에 우리가 신경을 쓸 필요가 거의 없다.
- 혹시라도 스프링 부트 없이 쓸 때는 `AbstractSecurityWebApplicationInitializer`를 상속 받아서 쓰면 된다.
- 그러면 `DelegatingFilterProxy`가 자동으로 등록 된다.
- 이렇게 해서 인증까지 봤는데 인가(Access Control)는 누가 하냐면 `AccessDecisionManager`가 한다.
- `AccessDecisionManager`가 내부적으로 `AccessDecisionVoter` 여러 개를 쓰고 있다.
- 그리고 `AccessDecisionManager`는 `FilterSecurityInterceptor`가 사용을 하는데 `FilterChainProxy` 필더 중에 하나이다. 

다음 수업에서는 인증과 인가 처리시에 발생하는 예외가 어떻게 처리 되는지 왜 dashboard를 요청했는데 login페이지로 가는지에 대해서 살펴본다. 

### 19강 - ExceptionTranslationFilter
앞서 본 FilterSecurityInterceptor에서 발생한 AccessDeniedException과 AuthenticationException을 처리 하는 필터
- **AuthenticationException(인증 예외) 발생시**
  - AuthenticationEntryPoint 실행
  - AbstractSecurityInterceptor 하위 클래스(ex: FilterSecurityInterceptor)에서 발생하는 예외만 처리한다.
  - 그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는 ? 
    - UsernamePasswordAuthenticationFilter 안에서 failureHandler로 처리한다.
      - 세션에다 에러를 담아둔 다음에, 로그인 페이지에서 에러메세지를 출력 한다.
- **AccessDeniedException(인허가 예외) 발생시**
  - 익명 사용자라면 AuthenticationEntryPoint를 실행한다.
  - 익명 사용자가 아니면 AccessDeniedHandler에게 위임한다.

### 20강 - 스프링 시큐리티 아키텍처 정리
![img_6.png](assets/img_6.png)

시큐리티 컨테이너에 요청이 들어오면 서블릿 필터 중에서 DeligatingFilterProxy가 FilterChainProxy라는 빈 이름으로 위임해 요청들을 처리한다. 여러 시큐리티 필터들은 내부적으로 체인 형태로 가지고 있다. 

FilterChainProxy은 WebSecurity를 가지고 만든다. WebSecurityConfiguration 을 사용하면 WebSecurity를 가지고 FilterChainProxy를 만든다. 이 체인이 DeligatingFilterProxy 필터가 위임하는 바로 그 체인이다. WebSecurityConfiguration은 WebSecurityConfigurationAdapter로 커스터마이징 할 수 있다. 

시큐리티 필터들이 사용하는 주요한 객체들이 있는데, 특히 인증과 관련해서는 AuthenticationManager를 사용한다. 그리고 인가(AccessControl)와 관련해서는 AccessDecisionManager를 사용한다. 인증에서 가장 중요한 이터페이스는 AuthenticationManager이고 구현체로는 대부분 기본적으로 제공되는 구현체인 ProviderManager 를 사용한다. 

ProviderManager는 다른 여러 AuthenticationProvider를 사용해서 인증을 처리한다. 그 중에 하나가 DaoAuthenticationProvider이다. DaoAuthenticationProvider는 UserDetailsService라는 Dao인터페이스를 사용해서 데이터에서 읽어온 유저정를 사용해서 인증을 한다. 데이터에서 읽어온 유저정보와 사용자가 입력한 username, password 가 일치하는지 확인하는 식으로 인증을 거친다. 인증에 성공하면 그 인증정보를 SecurityContextHolder에 넣어 놓고 어플리케이션 전반에 걸쳐서 사용한다. 

SecurityContextHolder안에 들어있는 Authentication 정보에는 Principal과 GrantedAuthorities가 있다. 이 정보들은 인증을 한 다음에 담기게 된다. 혹은 세션에 저장이 되고, 세션에 저장되어있던 정보가 SecurityContextPersistenceFilter에 의해 읽혀지기도 한다. 그렇게 인증이 됬다면 최종적으로 인가를 처리하는 필터인 FilterSecurityInterceptor가 AccessDecisionManager를 사용해서 인가 처리를 한다. 

현재 인증되어져 있는 Authentication이 접근하려는 리소스(특정 URL, 특정 메서드)에 적절한 ROLE을 가지고 있는지를 확인한다. 확인하는 방법은 기본적으로 3가지가 있다. 그 중에 AffirmativeBased를 기본전략으로 사용한다. AffirmativeBased은 여러 AccessDecisionVoter 중에 한명이라도 허용한다면 리소소를 허용한다. AffirmativeBased 말고도 다수결(ConsensusBased), 만장일치(UnanimousBased)가 있다. 

AffirmativeBased가 사용하는 Voter 중에 WebExpressionVoter는 SecurityExpressionHandler를 사용해서 Expression을 처리한다. SecurityExpressionHandler을 사용해서 계층형 ROLE을 설정할 수 있다.

### 21강 - 스프링 시큐리티 ignoring() 1부
WebSecurity의 ignoring()을 사용해서 시큐리티 필터 적용을 제외할 요청을 설정할 수 있다.

- 현재 웹페이지를 요청 했을 때 모든 요청에 대해 모든 시큐리티 필터들을 적용한다.
- 파비콘에 관련된 요청 처리를 아무 것도 하지 않았을 경우에 http://localhost:8080/ 로 웹페이지를 요청 할때 현재는 총 3가지의 요청이 간다. 

![img_7.png](assets/img_7.png)

1. localhost 요청을 보내면 favicon.ico 요청을 보낸다. 
2. 이 요청이 스프링 시큐리티 (.anyRequest().authenticated())에 걸려서 인증을 필요로 하는 요청으로 처리가 된다.
3. login요청으로 이어진다.

- 제대로 된 것 같이 보이지만, favicon.ico로 인해 필요 없는 로그인 요청이 생겼다.
- 그래서 이런 경우에, static 리소스 요청이면 시큐리티 필터를 적용 시키지 않도록 설정할 수 있다.
  - SecurityConfig에서 Websecurity를 받는 configure 메소드를 오버라이딩 한다. 
  - 제외하고 싶은 리소스의 URI 패턴으로 제외하고 싶을 떄는 mvcMatchers를 사용한다.
    ``` java
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().mvcMatchers("/favicon.ico");
    }
    ```
  - static 리소스 전체를 제외하고 싶을 떄는 requestMatchers를 사용한다.
    ``` java
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    ```
    - 스프링부트가 제공하는 PathRequest를 사용해서 정적 자원 요청을 스프링 시큐리티 필터를 적용하지 않도록 설정한다.

### 22강 - 스프링 시큐리티 ignoring() 2부
ignoring() 방법 중에는 아래 처럼 HttpSecurity를 사용해도 되지만 권장하지 않는다.
``` java
http.authorizeRequests()
        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll();
```
- 결과는 똑같지만 시큐리티 적용을 아예 안할 것 이라면 "21강 - 스프링 시큐리티 ignoring() 1부" 에서 소개한 방법이 더 추천 하는 방법이다.
- 왜냐하면, HttpSecurity를 받는 configure에서 authorizeRequests()에 걸리는 요청들은 모두 필터 체인(15개 필터)을 거치기 때문이다.   

### 23강 - Async 웹 MVC를 지원하는 필터: WebAsyncManagerIntegrationFilter
- 시큐리티 컨텍스트가 원래는 쓰레드 로컬을 사용하기 떄문에 자기자신의 동일한 스레드에서만 컨텍스트가 공유가 된다.
- 그리고 Async한 기능에서는 다른 쓰레드가 사용되어진다.
- 그런데 이 필터를 사용하면 다른 쓰레드지만 동일한 시큐리티 컨텍스트를 사용할 수 있다.

스프링 MVC의 Async 기능(핸들러에서 Callable)을 리턴할 수 있는 기능을 사용할 때에도 SecurityContext를 공유하도록 도와주는 필터
- PreProcess: SecurityContext를 설정한다.
- Callable: 비록 다른 쓰레드지만 그 안에는 동일한 SecurityContext를 참조할 수 있다.
- PostProcess: SecurityContext를 정리(clean up)한다.

``` java
@GetMapping("/async-handler")
@ResponseBody
public Callable<String> asyncHandler() {
    SecurityLogger.log("MVC"); // 이 영역은 톰캣이 할당해 준 nio 쓰레드
    return new Callable<String>() {
        @Override
        public String call() throws Exception {
            // 이영역은 별도의 쓰레드에서 동작
            SecurityLogger.log("Callable");
            return "Async Handler";
        }
    };
}
```
- Callable을 리턴하면 call 안의 내용이 처리되기 전에 이 Request를 처리하고 있던 쓰레드를 반환한다.
- call 안에서 하는 일이 완료가 되었을 때 쯤 그제서야 응답을 내보낸다.

실행 로그
```
MVC
Thread:http-nio-8080-exec-3
principal: org.springframework.security.core.userdetails.User [Username=keesun, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, credentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_USER]]
Callable
Thread:task-1
principal: org.springframework.security.core.userdetails.User [Username=keesun, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, credentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_USER]]
```

- 쓰레드가 다름에도 불구하고 동일한 principal이 참조 되었다.
- 이렇게 될 수 있도록 도와주는 필터가 WebAsyncManagerIntegrationFilter 이다.

### 24강 - 스프링 시큐리티와 @Async
이번 시간에는 지난 시간에 이어서 Async한 기능과 스프링 시큐리티가 어떻게 동작 하는지 알아본다. 
#### @Async 사용하기
``` java
@GetMapping("/async-service")
@ResponseBody
public String asyncService() {
    SecurityLogger.log("MVC, before async service");
    sampleService.asyncService();
    SecurityLogger.log("MVC, after async service");
    return "Async Service";
}
```
``` java
@Async
public void asyncService() {
    SecurityLogger.log("Async Servuce");
    System.out.println("Async service is called.");
}
```
``` java
@SpringBootApplication
@EnableAsync
public class DemoSpringSecurityFormApplication {
    ... 코드 생략 ...
}
```
- @Async 가 있으면 특정 빈안에 있는 메소드를 호출 할 때 별도의 쓰레드를 만들어서 비동기 적으로 호출된다.
- @Async만 사용한다고 Async하게 동작하지 않는다. 
- 스프링 부트 설정에 @EnableAsync 을 추가해야 한다.
- 하지만 위 코드는 principal을 공유하지는 않는다.

#### @Async 사용과 principal 공유
- 위 코드를 실행 시키면 principal에서 NullPointerException이 발생한다.
- principal을 공유하게 하려면 .setStrategyName()으로 시큐리티 정보를 어디까지 공유해줄 것인지 설정해 주어야 된다.

``` java
@Override
protected void configure(HttpSecurity http) throws Exception {
    ... 코드 생략 ...
    SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL); // 시큐리티 정보 공유 범위 설정
}
```
- 이렇게 해주면 다른 쓰레드에서도 같은 principal을 공유한다

### 25강 - SpringSecurity 영속화 필터: SecurityContextPersistenceFilter
- 인증을 한 다음에 다른 페이지로 이동해도 다시 인증을 하지 않게 해준다.
- 여러 요청 간에 SecurityConext 공유를 제공한다.
- SecurityContextRepository를 사용해서 기존의 SecurityContext를 읽어오거나 초기화한다.
  - 현재 요청과 관련 있는 SecurityContext를 SecurityContextRepository에서 읽어온다.
- 처음에 인증 안했을 때 비어있는 SecurityContext를 만드는데도 사용된다.
- 기본적으로 사용하는 전략은 HTTP Session을 사용한다.
- Spring-Session과 연동하여 세션 클러스트를 구현할 수 있다. 
- 모든 인증과 관련된 필터들 보다 더 위에 (전체 필터들 중 2번째) 선언이 되어져 았다.  
  - 참고로 나중에 커스텀한 인증 필터를 만들어서 적용 하려고 한다면 SecurityContextPersistenceFilter 보다 뒤에 등록 해야 된다.

### 26강 - 시큐리티 관련 헤더 추가하는 필터: HeaderWriterFilter
- 크게 신경쓰지 않아도 되는 필터이다. (설정할 일이 거의 없다)
- 어떤 일을 하는 지는 알아야 된다.
- 응답 헤더에 시큐리티 관련 헤더를 추가해 준다.
  - XContentTypeOptionsHeaderWriter: 마임 타입 스니핑 방어.
    - `X-Content-Type-Options: nosniff`
  - XXssProtectionHeaderWriter: 브라우저에 내장된 XSS 필터 적용.
    - `X-XSS-Protection: 1; mode=`
    - 브라우저에 내장되어 있는 XSS 필터를 활성화 한다.
    - 모든 XSS 공격을 막아주는 것은 아니기 때문에 Lucy 같은 XSS 필터를 추가해서 쓰는 것이 좋다.
  - CacheControlHeadersWriter: 캐시 히스토리 취약점 방어.
    - `Cache-Control: no-cache, no-store, max-age=0, must-revalidate`
    - `Expries: 0`
    - `Pragma: no-cache`
    - 캐시를 설정 하지 않는 이유는 동적인 리소스의 경우 민감한 정보들이 노출 될 수 있기 때문이다.
  - HstsHeaderWriter: HTTPS로만 소통하도록 강제.
    - (HTTPS를 설정 했을 때만 해당함)
  - XFrameOptionsHeaderWriter: clickjacking 방어.
    - `X-Frame-Option: DENY`

### 27강 - CSRF 어택 방지 필터: CsrfFilter
#### CSRF
  - https://namu.wiki/w/CSRF
  - 인증된 유저의 계정을 사용해 악의적인 변경 요청을 만들어 보내는 기법.
  - 내가 원치 않는 요청을 임의대로 만들어서 보내는 것
  - 특히 CORS를 사용할 때 주의 해야 한다.
    - 타 도메인에서 보내는 요청을 허용하기 때문에...
#### CsrfFilter
  - 의도한 사용자만 리소스를 변경할 수 있도록 허용하는 필터
  - CSRF 토큰을 사용하여 방지한다.
    - 리소스를 변경할 만한 요청에 대해서 CSRF 토큰을 만들어 보낸다.
    - Form에서 요청을 보낼 때 CSRF 토큰을 보내서 일치하는지 확인한다.
    - 기본 로그인 화면에서도 로그인 요청시 hidden으로 CSRF토큰을 보낸다.
    ```html
    <form class="form-signin" method="post" action="/login">
        ... 코드 생략 ...
        <input name="_csrf" type="hidden" value="643aa72d-6893-4ecc-a4a6-2b1a45faed3b">
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
    </form>
    ```
  - CSRFFilter를 사용하고 싶지 않을 때
    ``` java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ... 코드 생략 ...
        http.csrf().disable();
    }
    ```
    

### 28강 - CSRF 토큰 사용 예제
- **SecurityConfig.java**
  - mvcMatchers에 '/signup' path 추가 
``` java
... 코드 생략 ... 
@Configuration
@EnableWebSecurity
public class SecurityConifg extends WebSecurityConfigurerAdapter {
    ... 코드 생략 ... 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
        ... 코드 생략 ... 
    }
}
 
```

- **SignUpController.java**
``` java
... 코드 생략 ...
@Controller
@RequestMapping("/signup")
public class SignUpController {

    @Autowired AccountService accountService;

    @GetMapping
    public String signupForm(Model model) {
        model.addAttribute("account", new Account());
        return "signup";
    }

    @PostMapping
    public String processSignUp(@ModelAttribute Account account) {
        account.setRole("USER");
        accountService.createNew(account);
        return "redirect:";
    }
}
```

- **signup.html**
``` html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>SignUp</title>
</head>
<body>
    <form action="/signup" th:action="@{/signup}" th:object="${account}" method="post">
        <p>Username: <input type="text" th:field="*{username}"></p>
        <p>Password: <input type="text" th:field="*{password}"></p>
        <p><input type="submit" value="SignUp"></p>
    </form>
</body>
</html> 
```
- **html 화면**

![](assets/img_8.png)


- **랜더링된 html 소스 코드**
  - tymeleaf 2.1 버전 이상 혹은 JSP에서 form:form 태그를 사용하면 CSRF 토큰 input이 자동으로 생성된다.

![img.png](assets/img_9.png)

### 29강 - 로그아웃 처리 필터: LogoutFilter
- 로그아웃 요청을 처리하는 필터이다.
- 크게 두가지 핸들러가 있다.
  - LogoutHandler
    - Composite 타입 객체여서 여러 로그아웃 핸들러를 사용하고 있다.
    - 크게 두가지가 사용된다.
      - CsrfLoguntHandler
      - SecurityContextLogoutHandler
  - LogoutSuccessHandler
    - 로그아웃 처리를 끝낸 후에 어떤 처리를 할 것인지를 결정하는 핸들러이다.
- 로그아웃 했을 때 기본적으로는 로그인 페이지로 리다이렉트 된다. 
#### LogoutFilter 설정 방법
  - `http.logout()`
  - `.logoutUrl("/my/logout")`
    - 커스텀한 로그인 페이지를 만들었을 경우에 사용한다.
  - `.logoutSuccessUrl("/")`
    - 로그아웃 했을 때 리다이렉트 할 URL
  - `.addLogoutHandler()`
    - 로그아웃 처리가 다 끝난 다음에 logoutHandler를 별도로 추가할 수 있다.
  - `.logoutSuccessHandler()`
    - success 처리를 별도로 하고 싶을 때 사용한다.
  - `.invalidateHttpSession(true)`
    - 로그아웃 한다음에 http session을 invalid 처리 할 것인지 설정, 기본 값 = true, 커스터마이징 할 일이 거의 없다.
  - `.deleteCookies("name");`
    - 쿠키기반의 인증방법을 사용했을 경우에 쿠키를 삭제하려면 쿠키 이름을 인자로 주면 된다.

### 30강 - 폼 로그인을 처리하는 인증 필터: UsernamePasswordAuthenticationFilter
- 로그인 폼으로 로그인 요청을 했을 때, 그 요청을 처리하는 필터이다.
- 사용자가 폼에 입력한 usename과 password로 Authentication을 만들고 AuthenticationManager를 사용하여 인증을 시도한다.
- AuthenticationManager (ProviderManager)는 여러 AuthenticationProvider를 사용하여 인증을 시도한다.
- 그 중에 DaoAuthenticationProvider는 UserDetailService를 사용하여 UserDetails 정보를 가져와 사용자가 입력한 password와 비교한다.

### 31강 - DefaultLoginPageGeneratingFilter
- 기본 로그인 폼 페이지를 생성해주는 필터
  - GET /login 요청을 처리해주는 필터
#### 기본 로그인 화면
![img.png](assets/img_10.png)

- 파라미터 값을 원하는 대로 바꿀 수 있다.
  - ex) username -> my_username / password -> my_password 로 바꿀 수 있다.

    ``` java
    http.loginForm()
            .usernameParameter("my-username")
            .passwordParameter("my-password");
    ```
  - 위와 같은 설정을 주면 로그인 폼 html에서 input 태그의 name 값이 변경된다.
    ``` html
    ...
    <input type="text" id="username" name="my-username" class="form-control" placeholder="Username" required="" autofocus="">
    ...
    <input type="password" id="password" name="my-password" class="form-control" placeholder="Password" required="">
    ...
    ```

- 로그인 페이지를 새로 만들 수도 있다. 
    ``` java
    http.loginForm()
            .loginPage("/login").permitAll(); // 모든 사용자가 접근할 수 있게 permitAll()을 해줘야 한다.
    ```
    - 이렇게 설정한 순간 부터는 커서텀한 로그인 / 로그아웃 페이지를 써야 한다.
    - 그리고 DefaultLoginPageGeneratingFilter는 사용되지 않는다.
    - Debugger로 확인 하면 필터 목록에 DefaultLoginPageGeneratingFilter가 없는 것을 확인 할 수 있다.
    ![](assets/img_11.png)
    
### 32강 - 로그인 / 로그아웃 폼 커스터마이징

#### SecurityConfig.java
``` java
... 코드 생략 ...
public class SecurityConifg extends WebSecurityConfigurerAdapter {

    ... 코드 생략...
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ... 코드 생략 ...
        http.formLogin()
                .loginPage("/login").permitAll(); // 모든 사용자가 접근할 수 있게 permitAll()을 해줘야 한다.
        ... 코드 생략 ...
    }
}

```

#### LogInOutController.java
``` java
package me.whiteship.demospringsecurityform.account;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LogInOutController {

    @GetMapping("/login")
    public String loginForm() {
        return "/login";
    }
    @GetMapping("/logout")
    public String logoutForm() {
        return "/logout";
    }
}
```

#### login.html
``` html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <div th:if="${param.error}">
        Invalid username or password.
    </div>
    <form action="/login" method="post" th:action="@{/login}">
        <p>Username: <input type="text"></p>
        <p>Password: <input type="password"></p>
        <p><input type="submit" value="Login"></p>
    </form>
</body>
</html>
```

![img.png](assets/img_12.png)

#### logout.html
``` html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Logout</title>
</head>
<body>
    <h1>Logout</h1>
    <form action="/logout" method="post" th:action="@{/logiut}">
        <p><input type="submit" value="Logout"></p>
    </form>
</body>
</html>
```
![img_1.png](assets/img_13.png)

### 33강 - Basic 인증 처리 필터: BasicAuthenticationFilter
#### Basic 인증이란 ?
- HTTP 기본 인증 `http.httpBasic()`
- 요청 헤더에 usernaem과 password를 실어 보내면 브라우저 또는 서버가 그 값을 읽어서 인증하는 방식.
- ex) Authentication: Basic QWxhZGRpbjpPcGVuU2VzYW1l
  - username:password 를 Base64로 인코딩 한 값 (keesun:123)
- 보안에 취약하기 때문에 반드시 HTTPS를 사용할 것을 권장. (디코딩 할 수 있기 때문이다.)
- 보통 브라우저 기반 요청이 클라이언트의 요청을 처리할 때 사용.
- `curl -u lhm:123 http://localhost:8080` 해주면 `-u lhm:123` 정보를 기반으로 basic authentication 헤더를 만들어서 요청을 보낸다.
  - 잘못된 인증정보를 보내면 응답을 받을 수 없다.
#### UsernamePasswordAuthenticationFilter와의 차이
- UsernamePasswordAuthenticationFilter는 인증정보를 폼에서 읽어오는 것이 BasicAuthenticationFilter는 인증정보를 헤더에서 읽어온다.
- SecurityContext에 인증정보를 저장되지 않기 때문에 매번 인증정보를 보내야한다.

### 34강 - 요청 캐시 필터: RequestCacheAwareFilter
- 현재 요청과 관련 있는 캐시된 요청이 있는지 찾아서 적용하는 필터
  - 캐시된 요청이 없다면, 현재 요청 처리하고 
  - 캐시된 요청이 있다면, 해당 캐시된 요청 처리한다.

#### 예시
1. 로그인을 하지 않은채 로그인을 필요로하는 페이지로 요청을 보낸다.
2. AccessDecisionManager 의 판단하에 로그인 페이지로 이동한다.
3. 로그인 이후에 '캐시해둔 목적지 페이지로의 요청'을 처리해 가려했던 페이지로 이동하게 된다.

### 35강 - 시큐리티 관련 서블릿 스펙 구현 필터: SecurityContextHolderAwareRequestFilter
시큐리티 관련 서블릿 API를 구현 해주는 필터
- HttpServletRequest#authentication(HttpServletResponse)
- HttpServletRequest#login(String, String)
- HttpServletRequest#logout(logout)
- AsyncContext#start(Runnable)

RequestCacheAwareFilter 처럼 크게 신경 쓰지 않아도 되는 필터다.

### 36강 - 익명 인증 필터: AnonymousAuthenticationFilter
인증이 안된 사용자를 AnonymousAuthentication 객체로 만들어서 인증 정보를 SecurityContextHolder에 넣어 준다.
- 현재 SecurityContext에 Authentication이 null이면 "익명 Authentication"을 만들어 넣어주고, null이 아니면 아무일도 하지 않는다.

기본으로 만들어 사용할 "익명 Authentication"객체를 생성할 수 있다.

``` java
http.anonymous()
    .principal("nonMember") // 기본값 anonymousUser
    .authorities("ROLE_NONMEMBER") // 기본값 ROLE_ANONYMOUS 
    .key()
```

but. 굳이 커스터 마이징 할 이유가 없다.

### 37강 - SessionManagementFilter
세션 변조 방지 전략 설정: sessionFixation

유효하지 않는 세션을 리다이렉트 시킬 URL 설정: invalidSessionUrl

동시성 제어: maximumSessions
- 추가 로그인을 막을지 여부 설정(기본값, false)

세션 생성 전략: sessionCreationPolicy
- IF_REQUIRED
- NEVER
- STATELESS
- ALWAYS

