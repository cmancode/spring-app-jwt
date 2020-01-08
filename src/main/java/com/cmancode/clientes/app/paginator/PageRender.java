package com.cmancode.clientes.app.paginator;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Page;

public class PageRender<E> {
	
	private String url;
	private Page<E> page;
	
	private int totalPaginas;
	private int numElemPorPagina;
	private int paginaActual;
	
	private List<PageItem> paginas;
	
	public PageRender(String url, Page<E> page) {
		this.url = url;
		this.page = page;
		
		this.paginas = new ArrayList<PageItem>();
		
		numElemPorPagina = page.getSize(); // Obtenemos el número de elementos por página
		totalPaginas = page.getTotalPages();// Total de páginas
		paginaActual = page.getNumber() + 1; //Obtenemos la página actual
		
		int desde;
		int hasta;
		if(totalPaginas <= numElemPorPagina) {
			desde = 1;
			hasta = totalPaginas;
		}else {
			if(paginaActual <= (numElemPorPagina/2)) {
				desde = 1;
				hasta = numElemPorPagina;
			}else if(paginaActual >= (totalPaginas - (numElemPorPagina/2))) {
				desde = totalPaginas - numElemPorPagina + 1;
				hasta = numElemPorPagina;
			}else {
				desde = totalPaginas - (numElemPorPagina/2);
				hasta = numElemPorPagina;
			}
		}
		
		for(int i=0; i<hasta; i++) {
			PageItem pageItem = new PageItem(desde + i, (paginaActual == desde+i));
			paginas.add(pageItem);
			
		}
		
	}

	public String getUrl() {
		return url;
	}

	public int getTotalPaginas() {
		return totalPaginas;
	}

	public int getPaginaActual() {
		return paginaActual;
	}

	public List<PageItem> getPaginas() {
		return paginas;
	}
	
	public boolean isFirst() {
		return page.isFirst();
	}
	
	public boolean isLast() {
		return page.isLast();
	}
	
	public boolean isHasNext() {
		return page.hasNext();
	}
	
	public boolean isHasPrevious() {
		return page.hasPrevious();
	}
}
