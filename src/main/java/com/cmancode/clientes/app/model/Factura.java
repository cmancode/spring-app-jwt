package com.cmancode.clientes.app.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "facturas")
public class Factura implements Serializable {

	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY) // Autoincrementable en JPA
	private Long id;
	
	@NotEmpty
	@Column(nullable = false, length = 250)
	private String descripcion;
	
	@Column(nullable = true, length = 250)
	private String observacion;
	
	//@DateTimeFormat(pattern = "dd-MM-yyyy")
	@Temporal(TemporalType.DATE)
	private Date fecha;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(nullable = false)
	private Cliente cliente;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	@JoinColumn(name = "factura_id", nullable = false)
	@JsonIgnore
	private List<DetalleFactura> detalles;
	
	public Factura() {
		this.detalles = new ArrayList<DetalleFactura>();
	}
	
	@PrePersist
	public void prePersist() { //Crea la fecha al momento en que se cree la cactura
		this.fecha = new Date();
	}
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getDescripcion() {
		return descripcion;
	}

	public void setDescripcion(String descripcion) {
		this.descripcion = descripcion;
	}

	public String getObservacion() {
		return observacion;
	}

	public void setObservacion(String observacion) {
		this.observacion = observacion;
	}

	public Date getFecha() {
		return fecha;
	}

	public void setFecha(Date fecha) {
		this.fecha = fecha;
	}

	public Cliente getCliente() {
		return cliente;
	}

	public void setCliente(Cliente cliente) {
		this.cliente = cliente;
	}

	public List<DetalleFactura> getDetalles() {
		return detalles;
	}

	public void setDetalles(List<DetalleFactura> detalles) {
		this.detalles = detalles;
	}
	
	public void addItemFactura(DetalleFactura items) {
		this.detalles.add(items);
	}
	
	public Double getTotal() {
		Double total = 0.0;
		int size = this.detalles.size();
		for(int i=0; i < size; i++) {
			total += this.detalles.get(i).calcularImporte();
		}
		return total;
	}
	
	private static final long serialVersionUID = 1L;
	
}
