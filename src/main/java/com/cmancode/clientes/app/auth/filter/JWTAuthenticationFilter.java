package com.cmancode.clientes.app.auth.filter;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	
	private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	private AuthenticationManager authManager;
		
	
	//Se permite que realice la consulta con las credenciales ingresadas a la base de datos
	public JWTAuthenticationFilter(AuthenticationManager authManager) {
		this.authManager = authManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		String username = obtainUsername(request); //Métodos heredados
		String password = obtainPassword(request);

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}
		
		logger.info(username.concat(" ").concat(password));
		
		username = username.trim();
		
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		//El token se envía como argumento al authManager.authenticate() para proceder a autenticar
		return this.authManager.authenticate(authToken);
	}


	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		String username = authResult.getName();
		//String username = ((User) authResult.getPrincipal()).getUsername();
		
		//Gendering Token
		String tokenGenerated = Jwts.builder()
								.setSubject(username)
								.signWith(SECRET_KEY)
								.compact();
		
		response.addHeader("Authorization", "Bearer "+tokenGenerated);
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("token", tokenGenerated);
		body.put("username", username);
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}

}
