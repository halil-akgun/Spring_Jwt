package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private final String jwtSecret = "sboot";

    private final long jwtExpirationMs = 86400000;   // 24*60*60*1000 ( 1 gun )


    // !!! ********* GENERATE JWT TOKEN *************

    public String generateToken(Authentication authentication) {
        // Authentication ile login islemini gecmis olan kullaniciya ulasilir

        // anlik olarak login islemini gerceklestiren kullanici bilgisine ulastik :
        // securityContext'teki pojo'yu getirir
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // jwt tokeni userNAme field'i, jwtSecret ve jwtExpirationMs bilgilerini kullanarak olusturuyoruz
        return Jwts.builder(). // builder: sunlari kullanarak token uret
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date()).// JWT'nin "iat" (verilme tarihi) başlığını ayarlar.
                setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).// gecerlilik suresi
                signWith(SignatureAlgorithm.HS512, jwtSecret).
                compact(); // bohcalama/zipleme

    }


    // !!! ********* VALIDATE JWT TOKEN **************

    public boolean validateToken(String token) {

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException |
                 IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false;
    }


    // !!! ********* GET UserName FROm JWT TOKEN **********
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser(). // parser: parse ediyor / ayristiriyor / cozuyor..
                setSigningKey(jwtSecret).
                parseClaimsJws(token).
                getBody().
                getSubject();
    }

}