package com.tpe.security.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tpe.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Service
public class UserDetailsImpl implements UserDetails {

    private Long id;

    private String username;

    @JsonIgnore // client'a bu obje giderse password gitmesin
    private String password;

    private Collection<? extends GrantedAuthority> getAuthorities; // roller
    // bu Collection icine GrantedAuthority'den extends edilen herhangi bir obje alabilir

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    //!!! loadUSerByUserName kisminda kullanmak icin build()
    public static UserDetailsImpl build(User user){
        List<SimpleGrantedAuthority> authorities =
                user.getRoles().stream().
                        map(t-> new SimpleGrantedAuthority(t.getName().name())).
                        collect(Collectors.toList());
        return new UserDetailsImpl(user.getId(),
                user.getUserName(),
                user.getPassword(),
                authorities);
    }


    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
