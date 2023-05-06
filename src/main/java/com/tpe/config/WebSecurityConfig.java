package com.tpe.config;

import com.tpe.security.AuthTokenFilter;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired // @AllArgsConstructor koyunca @Autowired 'a gerek kalmadi - okunurluk icin yazlilabilir
    // constructor ile tum fieldlar otomatik enjekte edilir
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().      // REST mimari STATELESS oldugu icin:
                sessionManagement().//STATELESS olacagini (2 taraf arasinda session olmayacagini) belirtiyoruz
                sessionCreationPolicy(SessionCreationPolicy.STATELESS).
                and().
                authorizeRequests().
                antMatchers("/register", "/login").permitAll().
                anyRequest().authenticated();

        // authTokenFilter ekliyoruz
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // !!! dun yazdigimiz (springboot) kod blogunun kisa hali :
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

//  alttaki dun yazdigimiz kod. manager provider'dan daha yetkili (ustun)
//  userDetailsService ve passwordEncoder manager'a tanitilinca provider da tanimis oluyur

//    public DaoAuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setPasswordEncoder(passwordEncoder()); // encoder ile tanistirdim
//        authenticationProvider.setUserDetailsService(userDetailsService);//userDetailsService ile tanistirdim
//        return authenticationProvider;
//    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }


    @Bean // dun login islemi yapmadigimiz icin AuthenticationManager bean'i olusturmamistik
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
