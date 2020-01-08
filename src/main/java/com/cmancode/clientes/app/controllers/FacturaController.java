package com.cmancode.clientes.app.controllers;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.cmancode.clientes.app.model.Cliente;
import com.cmancode.clientes.app.model.DetalleFactura;
import com.cmancode.clientes.app.model.Factura;
import com.cmancode.clientes.app.model.Producto;
import com.cmancode.clientes.app.service.IClienteService;

//@Secured("ROLE_ADMIN")
@RequestMapping("/factura")
@Controller
@SessionAttributes("factura")
public class FacturaController {

	@Autowired
	private IClienteService clienteService;
	
	@GetMapping(value = "/ver/{id}")
	private String verFactura(@PathVariable("id") Long id, Model model, RedirectAttributes flash) {
		System.out.println("Entréeéééééééééeé");
		Factura factura = clienteService.findFactById(id);
		System.out.println("Fecha: "+factura.getFecha());
		
//		if(factura == null) {
//			flash.addFlashAttribute("error", "Factura no encontrada en la base de datos");
//			return "redirect:/clientes";			
//		}
		model.addAttribute("factura", factura);
		model.addAttribute("titulo", "Factura:".concat(factura.getDescripcion()));
		
		return "factura/ver";
	}
	
	@RequestMapping(value = "/factura/{clienteId}", method = RequestMethod.GET)
	public String crearFactura(@PathVariable("clienteId") Long id, Model model, RedirectAttributes flash) {
		
		Cliente cliente = clienteService.findById(id);
		if(cliente == null) {
			flash.addAttribute("info", "El cliente no existe en la base de datos");
			return "redirect: clientes";
		}
		
		Factura factura = new Factura();
		factura.setCliente(cliente);
		model.addAttribute("factura", factura);
		model.addAttribute("titulo", "Crear Factura");
		
		return "factura/factura";
	}
	
	@GetMapping(value = {"/cargar-productos/{nameProducto}"}, produces = "application/json")
	public @ResponseBody List<Producto> productos(@PathVariable("nameProducto") String nameProducto){
		return clienteService.productos(nameProducto);
	}
	
	@PostMapping(value = "/factura")
	public String guardarFactura (@Valid Factura factura, BindingResult resul,
			Model model,
			@RequestParam(name="item_id[]", required = false) Long[] itemId,
			@RequestParam(name="cantidad[]") Integer[] cantidad,
			RedirectAttributes flash,
			SessionStatus status) {
		
		if(resul.hasErrors()) {
			model.addAttribute("titulo", "Crear Factura");
			return "factura/factura";
		}
		
		for(int i=0; i<itemId.length; i++) {
			
			Producto producto = clienteService.findProductoById(itemId[i]);
			
			DetalleFactura linea = new DetalleFactura();
			
			linea.setCantidad(cantidad[i]);
			linea.setProducto(producto);
			
			factura.addItemFactura(linea);
		}
		
		clienteService.saveFactura(factura);
		status.setComplete();
		flash.addFlashAttribute("success", "Factura creada exitosamente!");
		
		return "redirect:/detalle/"+factura.getCliente().getId();
	}
	
}
