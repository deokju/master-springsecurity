package deok.springsecurity.config;

import deok.springsecurity.dao.CustomJdbcDaoImpl;
import deok.springsecurity.service.CustomFailHandler;
import deok.springsecurity.service.LoginSuccessHandler;
import deok.springsecurity.util.NonePasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource oneDataSource;

    @Autowired
    private LoginSuccessHandler loginSuccessHandler;

    @Autowired
    private CustomFailHandler customFailHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/css/**", "/index").permitAll()
                .antMatchers("/deokju/index").hasAuthority("A")
                .and()
                .formLogin()
                .loginPage("/login").defaultSuccessUrl("/deokju/index").failureUrl("/login-error")
                .successHandler(loginSuccessHandler)
                .failureHandler(customFailHandler);
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
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
