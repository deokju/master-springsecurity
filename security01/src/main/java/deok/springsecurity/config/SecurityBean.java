package deok.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityBean {

    private static final String STRING_EMPTY = "";

    @Bean
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() throws Exception{
        AffirmativeBased affirmativeBased = null;
        List<AccessDecisionVoter<? extends Object>> decisionVoterList = new ArrayList<>();
        RoleVoter roleVoter = new RoleVoter();
        roleVoter.setRolePrefix(STRING_EMPTY);

        decisionVoterList.add(roleVoter);

        affirmativeBased = new AffirmativeBased(decisionVoterList);
        affirmativeBased.setAllowIfAllAbstainDecisions(false);		// voter가 모두 기권할 경우 이것을 권한 허용으로 볼지의 여부(true이면 모두 기권할 경우 이것을 권한 허용으로 본다)
        return affirmativeBased;
    }

}
