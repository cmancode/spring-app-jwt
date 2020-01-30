package com.cmancode.clientes.app.auth;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAutoritiesMixin {

	@JsonCreator
	public SimpleGrantedAutoritiesMixin(@JsonProperty("authority") String roles) {
	}

}
