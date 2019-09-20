package com.deok.springsecurity.mapper.user;

import com.deok.springsecurity.entity.user.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper {
    User findUserByLoginId(@Param("loginId")String loginId);
    void setUserInfo(@Param("param")User user);
}
