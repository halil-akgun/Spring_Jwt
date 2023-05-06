package com.tpe.controller;

import com.tpe.controller.dto.LoginRequest;
import com.tpe.controller.dto.RegisterRequest;
import com.tpe.security.JwtUtils;
import com.tpe.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping
@AllArgsConstructor // enjekte icin Autowired'a gerek kalmiyor
public class UserJwtController {

    private UserService userService;

    private AuthenticationManager authenticationManager;

    private JwtUtils jwtUtils;

    // !!! ********************** REGISTER **************************
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest request) {

        userService.registerUser(request);

        String message = "User registered successfuly";
        return new ResponseEntity<>(message, HttpStatus.CREATED);

    }

    // !!! ********************** LOGIN **************************
    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest request) {

//      ********************** normalde service'de yazilir **********************
        // kullanici valide edilecek
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        // Authentication: valide edilen butun kullanicilari temsil eden class
        // security islemlerini bu class uzernden yapiyor

        String token = jwtUtils.generateToken(authentication);
//      ********************** normalde service'de yazilir **********************

        // ResponseEntity

        return new ResponseEntity<>(token, HttpStatus.CREATED);
    }

}