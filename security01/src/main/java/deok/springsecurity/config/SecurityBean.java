package deok.springsecurity.config;

import deok.springsecurity.dao.CustomJdbcDaoImpl;
import deok.springsecurity.service.ReloadableFilterInvocationSecurityMetadataSource;
import deok.springsecurity.service.SecuredObjectService;
import deok.springsecurity.service.SecuredObjectServiceImpl;
import deok.springsecurity.service.UrlResourcesMapFactoryBean;
import deok.springsecurity.util.NonePasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

@Configuration
public class SecurityBean {

    private static final String STRING_EMPTY = "";

    @Autowired
    private DataSource oneDataSource;

    @Bean
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        CustomJdbcDaoImpl  customJdbcDao = new CustomJdbcDaoImpl();
        customJdbcDao.setDataSource(oneDataSource);
        customJdbcDao.setRolePrefix("");
        customJdbcDao.setUsersByUsernameQuery("SELECT ID, PASSWORD, NAME FROM MEMBERINFO WHERE ID=?");
        //customJdbcDao.setAuthoritiesByUsernameQuery("SELECT ROLE_ID FROM MEMBER_ROLE WHERE ID=?");
        customJdbcDao.setAuthoritiesByUsernameQuery("SELECT AUTHORITY FROM MEMBER_AUTHORITY WHERE ID=?");
        customJdbcDao.setEnableGroups(false);

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customJdbcDao);
        authenticationProvider.setPasswordEncoder(new NonePasswordEncoder());
        return authenticationProvider;
    }


    @Bean
    public AccessDecisionManager accessDecisionManager() throws Exception{
        AffirmativeBased affirmativeBased = null;
        List<AccessDecisionVoter<? extends Object>> decisionVoterList = new ArrayList<>();
        RoleVoter roleVoter = new RoleVoter();
        roleVoter.setRolePrefix(STRING_EMPTY);

        decisionVoterList.add(roleVoter);

        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy())

        affirmativeBased = new AffirmativeBased(decisionVoterList);
        affirmativeBased.setAllowIfAllAbstainDecisions(false);		// voter가 모두 기권할 경우 이것을 권한 허용으로 볼지의 여부(true이면 모두 기권할 경우 이것을 권한 허용으로 본다)
        return affirmativeBased;
    }

    @Bean(initMethod="init")
    public UrlResourcesMapFactoryBean urlResourcesMapFactoryBean(SecuredObjectService securedObjectService){
        UrlResourcesMapFactoryBean urmfb = new UrlResourcesMapFactoryBean();
        urmfb.setSecuredObjectService(securedObjectService);
        return urmfb;
    }

    @Bean
    public ReloadableFilterInvocationSecurityMetadataSource reloadableFilterInvocationSecurityMetadataSource(UrlResourcesMapFactoryBean urmfb, SecuredObjectServiceImpl sosi) throws Exception{
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> destMap = new LinkedHashMap<>(urmfb.getObject());
        ReloadableFilterInvocationSecurityMetadataSource rfism = new ReloadableFilterInvocationSecurityMetadataSource(destMap);
        rfism.setSecuredObjectService(sosi);
        return rfism;
    }

    @Bean
    public RoleHierarchy roleHierarchy(SecuredObjectService securedObjectService) throws Exception {
        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
        //roleHierarchyImpl.setHierarchy(securedObjectService.getRolesHierarchy());
        return roleHierarchyImpl;
    }

}
