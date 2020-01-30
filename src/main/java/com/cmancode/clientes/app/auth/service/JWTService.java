package com.cmancode.clientes.app.auth.service;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


import io.jsonwebtoken.Claims;

public interface JWTService {
	
	public String createToken(Authentication auth) throws IOException;
	public boolean validateToken(String token);
	public Claims getClaims(String token);
	public String getUsername(String token);
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException;
	public String resolve(String token);
	
}
