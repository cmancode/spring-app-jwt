package com.cmancode.clientes.app.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cmancode.clientes.app.dao.IClienteDao;
import com.cmancode.clientes.app.dao.IFacturaDao;
import com.cmancode.clientes.app.dao.IProductoDao;
import com.cmancode.clientes.app.model.Cliente;
import com.cmancode.clientes.app.model.Factura;
import com.cmancode.clientes.app.model.Producto;

@Service("clienteService")
@Transactional
public class ClienteServiceImpl implements IClienteService{
	
	@Autowired
	private IClienteDao clienteDao;
	@Autowired
	private IProductoDao productoDao;
	@Autowired
	private IFacturaDao facturaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Cliente> findAll() {
		return (List<Cliente>) clienteDao.findAll();
	}

	@Override
	@Transactional
	public void saveClient(Cliente cliente) {
		clienteDao.save(cliente);
	}

	@Override
	@Transactional(readOnly = true)
	public Cliente findById(Long id) {
		return clienteDao.findById(id).orElse(null);
	}

	@Override
	@Transactional
	public void deleteClient(Long id) {
		clienteDao.deleteById(id);
	}

	@Override
	@Transactional
	public Page<Cliente> findAll(Pageable pageable) {
		Page<Cliente> clientePageable = null;
		clientePageable = clienteDao.findAll(pageable);
		return clientePageable;
	}

	@Override
	@Transactional
	public List<Producto> productos(String nameProducto) {
		return productoDao.productos(nameProducto);
	}

	@Override
	@Transactional
	public void saveFactura(Factura factura) {
		facturaDao.save(factura);		
	}

	@Override
	@Transactional(readOnly = true)
	public Producto findProductoById(Long id) {
		// TODO Auto-generated method stub
		return productoDao.findById(id).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public Factura findFactById(Long id) {
		return facturaDao.findById(id).orElse(null);
	}

	
}
