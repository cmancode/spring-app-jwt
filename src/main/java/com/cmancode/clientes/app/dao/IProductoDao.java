package com.cmancode.clientes.app.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.cmancode.clientes.app.model.Producto;

public interface IProductoDao extends CrudRepository<Producto, Long>{
	
	@Query("select p from Producto p where p.nombre like %?1%")
	public List<Producto> productos(String nameProducto);
	
}
