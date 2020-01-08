package com.cmancode.clientes.app.dao;

import org.springframework.data.repository.CrudRepository;

import com.cmancode.clientes.app.model.Factura;

public interface IFacturaDao extends CrudRepository<Factura, Long> {

}
