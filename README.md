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