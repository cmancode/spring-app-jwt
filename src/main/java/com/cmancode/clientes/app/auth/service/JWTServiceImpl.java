package com.cmancode.clientes.app.auth.service;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.cmancode.clientes.app.auth.SimpleGrantedAutoritiesMixin;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTServiceImpl implements JWTService {
	
	private static final Logger logger = LoggerFactory.getLogger(JWTServiceImpl.class);
	public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

	@Override
	public String createToken(Authentication auth) throws IOException {

		String username = auth.getName();
		//String username = ((User) authResult.getPrincipal()).getUsername();
		
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		
		Claims reclamandoRoles = Jwts.claims();
		reclamandoRoles.put("authorities", new ObjectMapper().writeValueAsString(roles));
		
		//Gendering Token
		String tokenGenerated = Jwts.builder()
				.setClaims(reclamandoRoles) //Roles
				.setSubject(username) //User
				.signWith(SECRET_KEY)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 3600000L))
				.compact();
		
		return tokenGenerated;
	}

	@Override
	public boolean validateToken(String token) {
		try {
			this.getClaims(token);
			logger.info("Token Validated");
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			logger.info("Token not Validated");
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		
		logger.info(this.resolve(token));
		
		Claims tokenData = Jwts.parser()
				.setSigningKey(SECRET_KEY)
				.parseClaimsJwt(this.resolve(token))
				.getBody();
		
		return tokenData;
	}

	@Override
	public String getUsername(String token) {
		// TODO Auto-generated method stub
		return this.getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		
		Object roles = this.getClaims(token).get("authorities");
		Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAutoritiesMixin.class)	
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		
		return authorities;
	}

	@Override
	public String resolve(String token) {
		// TODO Auto-generated method stub
		return token.replace("Bearer ", "");
	}

}
