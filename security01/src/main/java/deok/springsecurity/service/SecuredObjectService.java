package deok.springsecurity.service;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

public interface SecuredObjectService {

    /**
     * 룰에 대한 URL의 매핑 정보를 얻어온다.
     * @return
     * @throws Exception
     */
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getRolesAndUrl() throws Exception;


    /**
     * 룰에 대한 AOP pointcut 매핑 저보를 얻어온다.
     * @return
     * @throws Exception
     */
    public LinkedHashMap<String, List<ConfigAttribute>> getRolesAndMethod() throws Exception;

    /**
     * 룰에 대한 AOP pointcut 메핑 정보를 얻어온다.
     * @return
     * @throws Exception
     */
    public LinkedHashMap<String, List<ConfigAttribute>> getRolesAndPointcut() throws Exception;

    /**
     * Best 매칭 정보를 얻어온다.
     * @param url
     * @return
     * @throws Exception
     */
    public List<ConfigAttribute>  getMatchedRequestMapping(String url) throws Exception;

    /**
     * 룰의 계층적 구조를 얻어온다.
     * @return
     * @throws Exception
     */
    public String getHierachicalRoles() throws Exception;

}
