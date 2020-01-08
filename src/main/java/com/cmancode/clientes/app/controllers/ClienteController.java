package com.cmancode.clientes.app.controllers;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.cmancode.clientes.app.model.Cliente;
import com.cmancode.clientes.app.paginator.PageRender;
import com.cmancode.clientes.app.service.IClienteService;
import com.cmancode.clientes.app.service.IUploadFileService;

@Controller
public class ClienteController {

	@Autowired
	private IClienteService clienteService;
	@Autowired
	private IUploadFileService uploadServie;
	
	
	@Secured("ROLE_USER")
	@RequestMapping(value = "/detalle/{id}", method = RequestMethod.GET)
	public String detalleCliente(@PathVariable("id") Long id, Model model, RedirectAttributes flash) {
		
		Cliente cliente = clienteService.findById(id);

		if(cliente == null) {
			flash.addFlashAttribute("info", "El cliente no existe en la base de datos");
			return "redirect:clientes";
		}
		
		model.addAttribute("client", cliente);
		model.addAttribute("titulo", "Detalle de cliente");
		
		return "detalle";
	}
	
	
	@RequestMapping(value = {"/","/clientes"}, method = RequestMethod.GET)
	public String listarClientes(@RequestParam(name = "page", defaultValue = "0") int page, Model model) {
		Page<Cliente> clientesPageable = null;
		Pageable pageRequest = null;
		PageRender<Cliente> pageRender;
		pageRequest = PageRequest.of(page, 4);
		clientesPageable = clienteService.findAll(pageRequest);
		pageRender = new PageRender<>("/clientes", clientesPageable);
		model.addAttribute("titulo", "Lista de clientes");
		model.addAttribute("clientes", clientesPageable);
		model.addAttribute("page", pageRender);
		return "clientes";
	}
	@GetMapping(value = "/clientess")
	public ResponseEntity<List<Cliente>> clientes(){
		
		List<Cliente> clientes = null;
		
		clientes = clienteService.findAll();
		
		return new ResponseEntity<List<Cliente>>(clientes, HttpStatus.OK);
	}
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/cliente", method = RequestMethod.GET)
	public String nuevoCliente(Model model) {
		Cliente cliente = new Cliente();
		model.addAttribute("cliente", cliente);
		model.addAttribute("titulo", "Nuevo cliente");
		model.addAttribute("encabezado", "Nuevo Cliente");
		model.addAttribute("boton", "Registrar Cliente");
		return "nuevo-cliente";
	}
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/cliente", method = RequestMethod.POST)
	public String saveClient(@Valid Cliente cliente, BindingResult result, @RequestParam("file") MultipartFile file, RedirectAttributes flash, Model model) {
		
		String nameFoto = null;
		
		if(result.hasErrors()) {
			model.addAttribute("encabezado", "Nuevo Cliente");
			model.addAttribute("boton", "Registrar cliente");
			return "nuevo-cliente";
		}
		
		if(!file.isEmpty()) {
			if(cliente.getFoto() != null && cliente.getId() != null) { //Eliminamos foto al momento de actualizar foto
				uploadServie.deteleFile(cliente.getFoto());
			}
			nameFoto = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
			try {
				uploadServie.load(nameFoto, file); //Se copia la imagen a la ruta absoluta
			} catch (IOException e) {
				e.printStackTrace();
			}
			flash.addFlashAttribute("info", "Imagen '"+ nameFoto + "' almacenada con éxito!");
			cliente.setFoto(nameFoto);
		}
		flash.addFlashAttribute("success", "Información registrada con éxito!");
		clienteService.saveClient(cliente);
		return "redirect:/clientes";
	}
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/cliente/{id}", method = RequestMethod.GET)
	public String findByIdClient(@PathVariable("id") Long id, Cliente cliente, Model model) {
		
		if(id > 0) {
			cliente = clienteService.findById(id);
		}else {
			return "redirect: clientes";
		}
		model.addAttribute("encabezado", "Actualizar Cliente");
		model.addAttribute("boton", "Actualzar");
		model.addAttribute("cliente", cliente);
		return "nuevo-cliente";
	}
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/eliminar/{id}", method = RequestMethod.GET)
	public String deleteClient (@PathVariable("id") Long id, RedirectAttributes flash) {
		
		Cliente cliente = clienteService.findById(id);
		if(id > 0) {
			clienteService.deleteClient(id);
			uploadServie.deteleFile(cliente.getFoto()); //Eliminación de la imagen
			flash.addFlashAttribute("info", "Imagen "+ cliente.getFoto() +" eliminada con éxito!");
		}
		flash.addFlashAttribute("warning", "Datos eliminados con exitosamente!");
		return "redirect:/clientes";
	}
	
	
	public boolean hasRole(String role) {
		
		SecurityContext context = SecurityContextHolder.getContext();
		
		if(context == null) {
			return false;
		}
		
		Authentication auth = context.getAuthentication();
		
		if(auth == null) {
			return false;
		}
		
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		
		for(GrantedAuthority auth1: authorities) {
			if(role.equals(auth1.getAuthority())) {
				return true;
			}
		}
		
		return false;		
		
	}
}
