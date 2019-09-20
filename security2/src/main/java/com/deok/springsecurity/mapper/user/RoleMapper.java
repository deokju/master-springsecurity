package com.deok.springsecurity.mapper.user;

import com.deok.springsecurity.entity.user.Role;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface RoleMapper {
    Role getRoleInfo(@Param("role") String role);
}
