package com.cmancode.clientes.app.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.cmancode.clientes.app.auth.service.JWTService;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		//Getting attribute "Bearer" of Header 
		String headerToken = request.getHeader("Authorization");

		if (!requiresAuthentication(headerToken)) {
			chain.doFilter(request, response);
			
			return;
		}
		
		UsernamePasswordAuthenticationToken authentication = null;
		
		if(this.jwtService.validateToken(headerToken)) {
			//Doing authentication with token generated in the start authentication
			
			authentication = new UsernamePasswordAuthenticationToken(this.jwtService.getUsername(headerToken), null, this.jwtService.getRoles(headerToken));
			
		}
		//assigning the authentication to context the session
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	protected boolean requiresAuthentication(String headerToken) {
		if (headerToken == null || !headerToken.startsWith("Bearer ")) {
			return false;
		}
		return true;
	}
	
	
}
