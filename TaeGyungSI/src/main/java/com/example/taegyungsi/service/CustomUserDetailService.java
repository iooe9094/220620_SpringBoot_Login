package com.example.taegyungsi.service;

import com.example.taegyungsi.dao.UserDao;
import com.example.taegyungsi.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * packageName : com.example.taegyungsi.service
 * fileName : CustomUserDetailService
 * author : macbook
 * date : 6/20/22
 * description : 유저의 정보를 얻기 위한 서비스
 *               (id, 이름, 이메일, 패스워드)
 * ===========================================================
 * DATE            AUTHOR             NOTE
 * -----------------------------------------------------------
 * 6/20/22         macbook          최초 생성
 */

@Service // springboot 객체 생성
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    UserDao userDao; // 객체 정의(null -> 스프링객체 받기)

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        return userDao.findById(id);
    }

    public UserDetails findByName(String name) {
        return userDao.findByName(name);
    }

    // 유저 객체가 null이면 insert하고, 아니면 -1 반환하는 메소드
    public int singInUser(User user) {
        if(userDao.findByName(user.getUsername()) == null) {
            return userDao.insertUser(user);
        } else {
            return -1;
        }
    }
}
