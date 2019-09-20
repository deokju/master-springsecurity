package deok.springsecurity.vo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.*;

public class MemberInfo implements UserDetails {

    private String id;                          // 계정 아이디
    private String password;                    // 계정 비밀번호
    private String name;                        // 계정 사용자의 이름
    private Set<GrantedAuthority> authorities;  // 계정이 가지고 있는 권한 목록

    public MemberInfo(String id, String password, String name, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.password = password;
        this.name = name;
        this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
    }


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
    }

    // 계정이 갖고 있는 권한 목록을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    //계정의 이름을 리턴한다.(계정 ID)
    @Override
    public String getUsername() {
        return getId();
    }

    // 계정이 의 패스워드를 리턴한다
    @Override
    public String getPassword() {
        return password;
    }

    // 계정이 만료되지 않았는지를 리턴한다(true를 리턴하면 만료되지 않음을 의미)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있지 않은지를 리턴한다(true를 리턴하면 계정이 잠겨있지 않음을 의미)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정의 패스워드가 만료되지 않았는지를 리턴한다.(true를 리턴하면 패스워드가 만료되지 않음을 의미)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 사용가능한 계정인지를 리턴한다(true를 리턴하면 사용가능한 계정인지를 의미)
    @Override
    public boolean isEnabled() {
        return true;
    }

    private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
        SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(new AuthorityComparator());

        for (GrantedAuthority grantedAuthority : authorities) {
            Assert.notNull(grantedAuthority, "GrantedAuthority list cannot contain any null elements");
            sortedAuthorities.add(grantedAuthority);
        }
        return sortedAuthorities;
    }

    private static class AuthorityComparator implements Comparator<GrantedAuthority>, Serializable {

        @Override
        public int compare(GrantedAuthority g1, GrantedAuthority g2) {
            if (g2.getAuthority() == null) {
                return -1;
            }

            if (g1.getAuthority() == null) {
                return 1;
            }

            return g1.getAuthority().compareTo(g2.getAuthority());
        }
    }
}
