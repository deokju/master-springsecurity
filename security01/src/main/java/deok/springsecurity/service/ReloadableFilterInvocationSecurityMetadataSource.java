package deok.springsecurity.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;
import sun.misc.Request;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Map;

@Service
public class ReloadableFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    @Autowired
    private SecuredObjectService securedObjectService;


    public ReloadableFilterInvocationSecurityMetadataSource(Map<RequestMatcher, Collection<ConfigAttribute>> requestMap) {
        this.requestMap = requestMap;
    }

    private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;


    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        HttpServletRequest request = ( (FilterInvocation)object ).getRequest();
        Collection<ConfigAttribute> result = null;

        for(Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap.entrySet()) {
            if(entry.getKey().matches(request)) {
                result = entry.getValue();
                break;
            }
        }

        return result;

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return false;
    }
}
