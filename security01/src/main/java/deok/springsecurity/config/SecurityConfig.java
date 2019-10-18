package deok.springsecurity.config;

import deok.springsecurity.dao.CustomJdbcDaoImpl;
import deok.springsecurity.service.*;
import deok.springsecurity.util.NonePasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;
import java.util.Collection;

@Configuration
@Import({SecurityBean.class})
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDecisionManager accessDecisionManager;

    @Autowired
    private LoginSuccessHandler loginSuccessHandler;

    @Autowired
    private CustomFailHandler customFailHandler;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private DaoAuthenticationProvider daoAuthenticationProvider;

    private FilterSecurityInterceptor filterSecurityInterceptor;

    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor(AuthenticationManager authenticationManager,
                                                                     AccessDecisionManager accessDecisionManager,
                                                                     ReloadableFilterInvocationSecurityMetadataSource rfisms){
        FilterSecurityInterceptor customFilterSecurityInterceptor = new FilterSecurityInterceptor();
        customFilterSecurityInterceptor.setAuthenticationManager(authenticationManager);
        customFilterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager);	// AccessDecisionManager 설정
        customFilterSecurityInterceptor.setSecurityMetadataSource(rfisms);				    // SecurityMetadataSource 설정
        customFilterSecurityInterceptor.setRejectPublicInvocations(false);
        filterSecurityInterceptor  = customFilterSecurityInterceptor;
        return filterSecurityInterceptor;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {

        DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy);

        web.ignoring().antMatchers("/bootstrap/**/*", "/js/**/*")
                .and()
                .privilegeEvaluator(webInvocationPrivilegeEvaluator()) 		// webInvocationPrivilegeEvaluator() 메소드에 주석으로 설명되어 있으니 참조할 것
                .expressionHandler(defaultWebSecurityExpressionHandler);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(filterSecurityInterceptor ,FilterSecurityInterceptor.class)
                // .csrf().disable()			// Spring Security를 Java Config 방식으로 설정할 경우 CSRF 공격 방어 기능은 default로 동작한다. 이 설정을 하지 않을려고 할 경우에 사용한다
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/deokju/index")
                .failureUrl("/login-error")
                .successHandler(loginSuccessHandler)			// Login Success Handler 설정
                .failureHandler(customFailHandler)			    // Login Failure Handler 설정
                .and()
                .anonymous()
                .authorities("ANONYMOUS")
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .maximumSessions(1).expiredUrl("/sessionError.do?error=expired")			// 같은 로그인 아이디로 동시접속 할 수 있는 동시 접속자수를 정했는데 이 동시 접속자수를 초과해서 로그인 하게 되면 이동해야 할 URL을 지정하는 부분
                .maxSessionsPreventsLogin(true)										// 동시 접속자를 초과했을 경우 기존 로그인 한 사람의 세션을 끊을 것인지 아니면 신규 로그인 한 사람의 세션을 끊을것인지를 결정(true로 설정하면 신규 로그인 한 사람의 세션을 끊게 되고 이때 expiredUrl 메소드로 지정한 URL로 이동한다)
                .and()
                .invalidSessionUrl("/sessionError.do?error=invalid")
                .and()
/*                .exceptionHandling().accessDeniedHandler(customAccessDeniedHandler)		// Access Denied Handler 설정
                .and()*/
                .logout()
                // .logoutUrl("/logout.do")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))		// CSRF 기능 활성화된 상태에서 logout을 GET 방식으로 하게끔 할려면 logoutRequestMatcher메소드를 이용해서 메소드와 상관없이 동작하게끔 설정하면 된다
                .logoutSuccessUrl("/main.do").permitAll()
                .deleteCookies("JSESSIONID");
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider);
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager authenticationManager = super.authenticationManagerBean();
        return authenticationManager;
    }

}
