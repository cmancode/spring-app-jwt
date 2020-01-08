package com.cmancode.clientes.app.dao;

import org.springframework.data.repository.CrudRepository;

import com.cmancode.clientes.app.model.Usuario;

public interface IUsuarioDao extends CrudRepository<Usuario, Long> {
	
	public Usuario findByUsername(String username);
	
}
