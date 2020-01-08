package com.cmancode.clientes.app.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.cmancode.clientes.app.model.Cliente;
import com.cmancode.clientes.app.model.Factura;
import com.cmancode.clientes.app.model.Producto;

public interface IClienteService {
	
	public List<Cliente> findAll();
	public Page<Cliente> findAll(Pageable pageable);
	public void saveClient(Cliente cliente);
	public Cliente findById(Long id);
	public void deleteClient(Long id);
	public List<Producto> productos(String nameProducto);
	public void saveFactura(Factura factura);
	public Producto findProductoById(Long id);
	public Factura findFactById(Long id);
}
