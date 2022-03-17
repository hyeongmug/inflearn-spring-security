### 강의 주소
https://www.inflearn.com/course/백기선-스프링-시큐리티

## 학습 정리 
### 3강 - 스프링 시큐리티 연동

pom.xml 등록
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 4강 - 스프링 시큐리티 설정하기

SecurityConfig 클래스를 생성
```
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

- SecurityConfig 는 WebSecurityConfigurerAdapter 를 상속 받는다.
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

```  
spring.security.user.name=admin
spring.security.user.password=123
spring.security.user.roles=ADMIN
```  
#### 시큐리티 설정에 추가하는 방법
1. SecurityConfig 에서 AuthenticationManagerBuilder auth를 제공하는 configure메소드를 오버라이드 한다.
2. auth.inMemoryAuthentication() 호출
   - 하위 메소드로 withUser(), password(), role() 을 사용하여 유저 정보를 추가 할 수있다.
```   
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("keesun").password("{noop}123").roles("USER").and()
        .withUser("admin").password("{noop}!@#");
}
```
- {}안에 암호화 방법을 적는다.
  - noop은 스프링부트 기본 패스워더 인코더 
    - 비밀번호 앞에 {noop} 프리픽스가 있으면 noop으로 패스워드를 인코딩 한다.
