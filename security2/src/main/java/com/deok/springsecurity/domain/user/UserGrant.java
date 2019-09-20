package com.deok.springsecurity.domain.user;

import org.springframework.security.core.GrantedAuthority;

public class UserGrant implements GrantedAuthority {
    @Override
    public String getAuthority() {
        return "ADMIN";
    }
}
