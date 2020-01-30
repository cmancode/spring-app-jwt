package com.cmancode.clientes.app.auth.filter;

import java.io.IOException;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
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
import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

import com.cmancode.clientes.app.auth.service.JWTService;
import com.cmancode.clientes.app.model.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authManager;
	private JWTService jwtService;
	
	//Se permite que realice la consulta con las credenciales ingresadas a la base de datos
	public JWTAuthenticationFilter(AuthenticationManager authManager, JWTService jwtService) {
		this.authManager = authManager;
		//setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
		this.jwtService = jwtService;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		String username = obtainUsername(request); //Métodos heredados
		String password = obtainPassword(request);

		if(username != null && password != null) {
			logger.info("Datos ingresados por (form-data) username: "+username);
			logger.info("Datos ingresados por (form-data) username: "+password);
		}else {
			
			Usuario usuario = null;
			
			try {
				//Converting request data to User Class
				usuario = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
				username = usuario.getUsername();
				password = usuario.getPassword();
				
				logger.info("Datos ingresados por (raw) username: "+ username);
				logger.info("Datos ingresados por (raw) username: "+ password);
				
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		username = username.trim();
		
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		//El token se envía como argumento al authManager.authenticate() para proceder a autenticar
		return this.authManager.authenticate(authToken);
	}


	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		
		String tokenGenerated = this.jwtService.createToken(authResult);
		
		response.addHeader("Authorization", "Bearer "+tokenGenerated);
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("token", tokenGenerated);
		body.put("username", authResult.getName());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("mensaje", "El usuario o la contrasela es incorrecto");
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
		response.setContentType("application/json");
		
	}

	
	
	
}
