package deok.springsecurity.config;

import deok.springsecurity.dao.CustomJdbcDaoImpl;
import deok.springsecurity.service.*;
import deok.springsecurity.util.NonePasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AffirmativeBased;

import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;


import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;


@Configuration
@Import({SecurityBean.class})
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDecisionManager accessDecisionManager;

    @Autowired
    private DataSource oneDataSource;

    @Autowired
    private LoginSuccessHandler loginSuccessHandler;

    @Autowired
    private CustomFailHandler customFailHandler;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

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


/*        http
                .authorizeRequests()
                .antMatchers("/css/**", "/index").permitAll()
                .antMatchers("/deokju/index").hasAuthority("A")
                .and()
                .formLogin()
                .loginPage("/login").defaultSuccessUrl("/deokju/index").failureUrl("/login-error")
                .successHandler(loginSuccessHandler)
                .failureHandler(customFailHandler);*/

        //http.addFilterBefore(FilterSecurityInterceptor, )

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        CustomJdbcDaoImpl  customJdbcDao = new CustomJdbcDaoImpl();
        customJdbcDao.setDataSource(oneDataSource);
        customJdbcDao.setRolePrefix("");
        customJdbcDao.setUsersByUsernameQuery("SELECT ID, PASSWORD, NAME FROM MEMBERINFO WHERE ID=?");
        customJdbcDao.setAuthoritiesByUsernameQuery("SELECT ROLE_ID FROM MEMBER_ROLE WHERE ID=?");
        customJdbcDao.setEnableGroups(false);


        auth.authenticationProvider(authenticationProvider(customJdbcDao));
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider( CustomJdbcDaoImpl customJdbcDao ) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customJdbcDao);
        authenticationProvider.setPasswordEncoder(new NonePasswordEncoder());
        return authenticationProvider;
    }



    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager authenticationManager = super.authenticationManagerBean();
        return authenticationManager;
    }

}
