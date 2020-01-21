package com.cmancode.clientes.app.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cmancode.clientes.app.model.Cliente;
import com.cmancode.clientes.app.service.IClienteService;

@RequestMapping("/api/clientes")
@RestController
public class ClienteRestController {
	
	@Autowired
	private IClienteService clienteService;
	
	@GetMapping("/listar")
	public ResponseEntity<List<Cliente>> listarClientes(){
		
		List<Cliente> clientes = this.clienteService.findAll();
		
		return new ResponseEntity<List<Cliente>>(clientes, HttpStatus.OK);
	}
}
