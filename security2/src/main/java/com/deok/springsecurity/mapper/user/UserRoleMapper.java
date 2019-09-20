package com.deok.springsecurity.mapper.user;

import com.deok.springsecurity.entity.user.UserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Component;

@Mapper
public interface UserRoleMapper {
    void setUserRoleInfo(@Param("param") UserRole param);
}
