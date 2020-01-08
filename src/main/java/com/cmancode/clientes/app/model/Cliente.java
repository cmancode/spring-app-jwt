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
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.springframework.format.annotation.DateTimeFormat;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "clientes")
public class Cliente implements Serializable{


	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@NotEmpty
	@Column(nullable = false, length = 30)
	private String nombres;
	
	@NotEmpty
	@Column(nullable = false, length = 30)
	private String p_apellido;
	
	@NotEmpty
	@Column(nullable = false, length = 30)
	private String s_apellido;
	
	@NotEmpty
	@Column(length = 50)
	private String correo;
	
	@NotNull
	@Column(nullable = false)
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "dd-MM-yyyy")
	private Date fecha_nacimiento;
	
	@OneToMany(mappedBy = "cliente", fetch = FetchType.LAZY , cascade = CascadeType.ALL)
	@JsonIgnore
	private List<Factura> facturas; //Relación uno a muchos 
	
	@Column
	private String foto;
	
	
	public Cliente() {
		this.facturas = new ArrayList<Factura>();
	}
	public String getCorreo() {
		return correo;
	}
	public void setCorreo(String correo) {
		this.correo = correo;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getNombres() {
		return nombres;
	}
	public void setNombres(String nombres) {
		this.nombres = nombres;
	}
	public String getP_apellido() {
		return p_apellido;
	}
	public void setP_apellido(String p_apellido) {
		this.p_apellido = p_apellido;
	}
	public String getS_apellido() {
		return s_apellido;
	}
	public void setS_apellido(String s_apellido) {
		this.s_apellido = s_apellido;
	}
	public Date getFecha_nacimiento() {
		return fecha_nacimiento;
	}
	public void setFecha_nacimiento(Date fecha_nacimiento) {
		this.fecha_nacimiento = fecha_nacimiento;
	}
	public String getFoto() {
		return foto;
	}
	public void setFoto(String foto) {
		this.foto = foto;
	}
	public List<Factura> getFacturas() {
		return facturas;
	}
	public void setFacturas(List<Factura> facturas) {
		this.facturas = facturas;
	}
	public void addFactura(Factura factura) {
		this.facturas.add(factura);
	}
	@Override
	public String toString() {
		return  nombres + " " + p_apellido ;
	}

	
}
