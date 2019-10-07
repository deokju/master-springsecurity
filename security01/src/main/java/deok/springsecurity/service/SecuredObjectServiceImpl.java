package deok.springsecurity.service;

import deok.springsecurity.dao.SecuredObjectDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

@Service
public class SecuredObjectServiceImpl implements SecuredObjectService{

    @Autowired
    private SecuredObjectDao securedObjectDao;

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getRolesAndUrl() throws Exception {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> ret = new LinkedHashMap<>();
        LinkedHashMap<Object, List<ConfigAttribute>> data = securedObjectDao.getRolesAndUrl();

        Set<Object> keys = data.keySet();
        for(Object key : keys) {
            ret.put((AntPathRequestMatcher)key, data.get(key));
        }

        return ret;
    }

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getRolesAndMethod() throws Exception {
        LinkedHashMap<String, List<ConfigAttribute>> ret = new LinkedHashMap<>();
        LinkedHashMap<Object, List<ConfigAttribute>> data = securedObjectDao.getRolesAndMethod();
        Set<Object> keys = data.keySet();
        for(Object key : keys) {
            ret.put((String)key, data.get(key));
        }

        return ret;
    }

    @Override
    public LinkedHashMap<String, List<ConfigAttribute>> getRolesAndPointcut() throws Exception {
        LinkedHashMap<String, List<ConfigAttribute>> ret  = new LinkedHashMap<>();
        LinkedHashMap<Object, List<ConfigAttribute>> data = securedObjectDao.getRolesAndPointcut();

        Set<Object> keys = data.keySet();
        for(Object key : keys) {
            ret.put((String)key, data.get(key));
        }

        return ret;
    }

    @Override
    public List<ConfigAttribute> getMatchedRequestMapping(String url) throws Exception {
        return securedObjectDao.getRegexMatchedRequestMapping(url);
    }

    @Override
    public String getHierachicalRoles() throws Exception {
        return securedObjectDao.getHierachicalRoles();
    }
}
