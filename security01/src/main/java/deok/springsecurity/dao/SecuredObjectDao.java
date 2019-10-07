package deok.springsecurity.dao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.util.*;

@Component
public class SecuredObjectDao {

    /**
     *  url 형식인 보호자원 - Role 맵핑정보를 조회하는 default 쿼리이다.
     */
    public static final String DEF_ROLES_AND_URL_QUERY  =
              " SELECT A.RESOURCE_PATTERN AS URL, B.AUTHORITY AS AUTHORITY "
            + " FROM  SECURED_RESOURCE A, SECURED_RESOURCE_AUTHORITY B "
            + " WHERE A.RESOURCE_ID = B.RESOURCE_ID "
            + " AND A.RESOURCE_TYPE = 'url' "
            + " ORDER BY A.SORT_ORDER ";

    /**
     *  method 형식인 보호자원 - Role 맵핑정보를 조회하는 default 쿼리이다.
     */
    public static final String DEF_ROLES_AND_METHOD_QUERY =
            " SELECT A.RESOURCE_PATTERN AS URL, B.AUTHORITY AS AUTHORITY "
                    + " FROM  SECURED_RESOURCES A, SECURED_RESOURCES_ROLE B "
                    + " WHERE A.RESOURCE_ID = B.RESOURCE_ID "
                    + " AND A.RESOURCE_TYPE = 'method' "
                    + " ORDER BY A.SORT_ORDER ";

    /**
     *  pointcut 형식인 보호자원 - Role 맵핑정보를 조회하는 default 쿼리이다.
     */
    public static final String DEF_ROLES_AND_POINTCUT_QUERY =
            " SELECT A.RESOURCE_PATTERN AS POINTCUT, B.AUTHORITY AS AUTHORITY "
                    + " FROM  SECURED_RESOURCES A, SECURED_RESOURCES_ROLE B "
                    + " WHERE A.RESOURCE_ID = B.RESOURCE_ID "
                    + " AND A.RESOURCE_TYPE = 'pointcut' "
                    + " ORDER BY A.SORT_ORDER ";

    /**
     *  매 request 마다 best matching url 보호자원 -Role 맵핑정보를 얻기위한 default 쿼리이다.
     *  TODO 손을 따로 대지 않음.
     */
    public static final String DEF_REGEX_MATCHED_REQUEST_MAPPING_QUERY_ORACLE10G =
            " SELECT A.RESOURCE_PATTERN AS POINTCUT, B.AUTHORITY AS AUTHORITY "
                    + " FROM  SECURED_RESOURCES A, SECURED_RESOURCES_ROLE B "
                    + " WHERE A.RESOURCE_ID = B.RESOURCE_ID "
                    + " AND A.RESOURCE_TYPE = 'pointcut' "
                    + " ORDER BY A.SORT_ORDER ";

    /**
     *  Role 의 계층(Hierarchy) 관계를 조회하는 default 쿼리이다.
     */
    public static final String DEF_HIERARCHICAL_ROLES_QUERY =
            " SELECT a.child_role child, a.parent_role parent "+
            " FROM ROLES_HIERARCHY a LEFT JOIN ROLES_HIERARCHY b "+
            " ON (a.child_role = b.parent_role)";

    private String sqlRolesAndUrl;
    private String sqlRolesAndMethod;
    private String sqlRolesAndPointcut;
    private String sqlRegexMatchedRequestMapping;
    private String sqlHierarchicalRoles;


    @Autowired
    DataSource oneDataSource;

    public SecuredObjectDao()
    {
        this.sqlRolesAndUrl      = DEF_ROLES_AND_URL_QUERY;
        this.sqlRolesAndMethod   = DEF_ROLES_AND_METHOD_QUERY;
        this.sqlRolesAndPointcut = DEF_ROLES_AND_POINTCUT_QUERY;
        this.sqlRegexMatchedRequestMapping = DEF_REGEX_MATCHED_REQUEST_MAPPING_QUERY_ORACLE10G;
        this.sqlHierarchicalRoles = DEF_HIERARCHICAL_ROLES_QUERY;

        this.setDataSource(oneDataSource);
    }

    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;


    public void setDataSource( DataSource dataSource ) {
        this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    }

    public String getSqlRolesAndUrl() {
        return sqlRolesAndUrl;
    }

    public void setSqlRolesAndUrl(String sqlRolesAndUrl) {
        this.sqlRolesAndUrl = sqlRolesAndUrl;
    }

    public String getSqlRolesAndMethod() {
        return sqlRolesAndMethod;
    }

    public void setSqlRolesAndMethod(String sqlRolesAndMethod) {
        this.sqlRolesAndMethod = sqlRolesAndMethod;
    }

    public String getSqlRolesAndPointcut() {
        return sqlRolesAndPointcut;
    }

    public void setSqlRolesAndPointcut(String sqlRolesAndPointcut) {
        this.sqlRolesAndPointcut = sqlRolesAndPointcut;
    }

    public String getSqlRegexMatchedRequestMapping() {
        return sqlRegexMatchedRequestMapping;
    }

    public void setSqlRegexMatchedRequestMapping(String sqlRegexMatchedRequestMapping) {
        this.sqlRegexMatchedRequestMapping = sqlRegexMatchedRequestMapping;
    }

    public String getSqlHierarchicalRoles() {
        return sqlHierarchicalRoles;
    }

    public void setSqlHierarchicalRoles(String sqlHierarchicalRoles) {
        this.sqlHierarchicalRoles = sqlHierarchicalRoles;
    }

    public LinkedHashMap<Object, List<ConfigAttribute> > getRolesAndResources( String resourceType ) throws Exception {

        LinkedHashMap<Object, List<ConfigAttribute> > resourcesMap = new LinkedHashMap<Object, List<ConfigAttribute>>();

        String sqlRolesAndResources;
        boolean isResourcesUrl = true;

        if("method".equals(resourceType)) {
            sqlRolesAndResources = getSqlRolesAndMethod();
            isResourcesUrl = false;
        }else if("pointcut".equals(resourceType)) {
            sqlRolesAndResources = getSqlRolesAndPointcut();
            isResourcesUrl = false;
        }else {
            sqlRolesAndResources = getSqlRolesAndUrl();
        }

        List<Map<String, Object>> resultList =
                this.namedParameterJdbcTemplate.queryForList(sqlRolesAndResources, new HashMap<String, String>());
        Iterator<Map<String, Object>> itr = resultList.iterator();
        Map<String, Object> tempMap;
        String preResource = null;
        String presentResourceStr;
        Object presentResource;

        while(itr.hasNext()){
            tempMap = itr.next();
            presentResourceStr = (String) tempMap.get(resourceType);

            //url 인 경우 RequestKey 형식의 key를 Map에 담아야 함
            presentResource = isResourcesUrl ? new AntPathRequestMatcher(presentResourceStr) : presentResourceStr;
            List<ConfigAttribute> configList = new LinkedList<ConfigAttribute>();

            // 이미 requestMap에 해당 Resource에 대한 Role이 하나 이상 맵핑되어 있었던 경우,
            // sort_order는 resource(Resource)에 대해 매겨지므로 같은 Resource에 대한 Role 맵핑은 연속으로 조회됨.
            // 해당 맵핑 Role List (SecurityConfig) 의 데이터를 재활용하여 새롭게 데이터 구축
            if(preResource != null && presentResourceStr.equals(preResource)) {
                List<ConfigAttribute> preAuthList = resourcesMap.get(presentResource);
                Iterator<ConfigAttribute> preAuthltr = preAuthList.iterator();
                while(preAuthltr.hasNext()) {
                    SecurityConfig tempConfig = (SecurityConfig) preAuthltr.next();
                    configList.add(tempConfig);
                }
            }

            configList.add(new SecurityConfig( (String) tempMap.get("authority")));

            // 만약 동일한 Resource에 대해 한개 이상의 Role 맵핑 추가인 경우
            // 이전 resourceKey 에 현재 새로 계산된 Role 맵핑 리스트로 덮어쓰게 됨.
            resourcesMap.put(presentResource, configList);

            //이전 resource 비교위해 저장
            preResource = presentResourceStr;
        }

        return resourcesMap;
    }

    public LinkedHashMap<Object, List<ConfigAttribute>> getRolesAndUrl() throws Exception {
        return getRolesAndResources("url");
    }

    public LinkedHashMap<Object, List<ConfigAttribute>> getRolesAndMethod() throws Exception {
        return getRolesAndResources("method");
    }

    public LinkedHashMap<Object, List<ConfigAttribute>> getRolesAndPointcut() throws Exception {
        return getRolesAndResources("pointcut");
    }

    public List<ConfigAttribute> getRegexMatchedRequestMapping(String url) throws Exception {
        // best regex matching - best 매칭된 Uri에 다른 Role List 조회
        // DB 차원의 정규식 지원이 있는 경우 사용 (ex. hs

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put("url", url);
        List<Map<String, Object>> resultList =
                this.namedParameterJdbcTemplate.queryForList(getSqlRegexMatchedRequestMapping(), paramMap);

        Iterator<Map<String, Object>> itr = resultList.iterator();
        Map<String, Object> tempMap;
        List<ConfigAttribute> configList = new LinkedList<ConfigAttribute>();
        // 같은 Uri 에 대한 Role 맵핑이므로 무조건 configList에 add함
        while(itr.hasNext()) {
            tempMap = itr.next();
            configList.add(new SecurityConfig( (String)tempMap.get("authority")));
        }

        return configList;
    }

    public String getHierachicalRoles() throws Exception {
        List<Map<String, Object>> resultList =
                this.namedParameterJdbcTemplate.queryForList(getSqlHierarchicalRoles(), new HashMap<String, String>());

        Iterator<Map<String, Object>> itr = resultList.iterator();
        StringBuffer concatedRoles = new StringBuffer();
        Map<String, Object> tempMap;
        while(itr.hasNext()) {
            tempMap = itr.next();
            concatedRoles.append(tempMap.get("child"));
            concatedRoles.append(" > ");
            concatedRoles.append(tempMap.get("parent"));
            concatedRoles.append(" \n ");
        }

        return concatedRoles.toString();
    }


}
