package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired // user'a ulasmak icin enjekte edildi
    private UserDetailsService userDetailsService;
    // Service'i impl. eden 1 concrete class oldugu icin interface enj. etmek sorun olmaz

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // jwt tokeni requestin icinden almamiz gerekiyor
        String jwtToken = parseJwt(request);

        try {
            if (jwtToken != null && jwtUtils.validateToken(jwtToken)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

//          buradan itibaren context'e koyma islemi
//          Basic Auth'da otomatik yapiliyordu ama JWT'de biz yapiyoruz
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // ekstra datalar burada ekleniyor
                                userDetails.getAuthorities() // rollerini getir
                        );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request, response);

    }

    // !!! requestin icindeki JWT tokeni cikartan method
    private String parseJwt(HttpServletRequest request) {

        // token header'da bulunur
        String header = request.getHeader("Authorization");//Authorization key'inin value'sini getir
        // token oldugu anlasilsin diye basina "Bearer " konulmus. ornek token:
        // Bearer sdfdfgdfwfqdfsdfgdghfewf.dasddassf5gewfgs5dgfdg.fadda55dsad2452afgggfsd

        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
//      startsWith daha fazla performans gerektiren bir method oldugu icin once text var mi diye baktik

            return header.substring(7);
        }
        return null;
    }

    // alttaki methodun permitAll() dan farki:
    // permitAll() da kimlik kontrolu yapilmayacak end-pointler belirtilirken
    // shouldNotFilter() da icinde bulundugumuz filtreye girmesini istemedigimiz end-pointleri yaziyoruz
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return antPathMatcher.match("/register", request.getServletPath()) ||
                antPathMatcher.match("/login", request.getServletPath());
    }
}
