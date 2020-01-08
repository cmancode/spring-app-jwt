package com.cmancode.clientes.app.dao;

import org.springframework.data.repository.PagingAndSortingRepository;

import com.cmancode.clientes.app.model.Cliente;

public interface IClienteDao extends PagingAndSortingRepository<Cliente, Long>{

}
