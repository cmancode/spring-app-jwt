package com.cmancode.clientes.app.view.pdf;

import java.awt.Color;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractPdfView;

import com.cmancode.clientes.app.model.DetalleFactura;
import com.cmancode.clientes.app.model.Factura;
import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfCell;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

@Component("factura/ver")
public class FacturaPdfView extends AbstractPdfView {

	@Override
	protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer,
			HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		Factura factura = (Factura) model.get("factura");
		
			
		PdfPTable t = new PdfPTable(1);
		t.setSpacingAfter(20);
		
		PdfPCell cell = null;
		cell = new PdfPCell(new Phrase("Datos del Cliente"));
		cell.setBackgroundColor(new Color(184, 218, 255));
		cell.setPadding(8f);		
		
		t.addCell(cell);
		t.addCell(factura.getCliente().getNombres()+" "+factura.getCliente().getP_apellido());
		t.addCell(factura.getCliente().getCorreo());
		
		PdfPTable t2 = new PdfPTable(1);
		t2.setSpacingAfter(20);
		cell = new PdfPCell(new Phrase("Datos de la Factura"));
		cell.setBackgroundColor(new Color(195, 230, 203));
		cell.setPadding(8f);
		
		t2.addCell(cell);
		t2.addCell("Folio: "+factura.getId());
		t2.addCell("Descripción: "+factura.getDescripcion());
		t2.addCell("Fecha: "+factura.getFecha());
		
		PdfPTable t3 = new PdfPTable(4);
		t3.setWidths(new float[] {3.5f, 1, 1, 1});
		t3.addCell("Producto");
		t3.addCell("Precio");
		t3.addCell("Cantidad");
		t3.addCell("Total");
		
		for(DetalleFactura detalle: factura.getDetalles()) {
			t3.addCell(detalle.getProducto().getNombre());
			t3.addCell(detalle.getProducto().getPrecio().toString());
			cell = new PdfPCell(new Phrase(detalle.getCantidad().toString()));
			cell.setHorizontalAlignment(PdfCell.ALIGN_CENTER);
			t3.addCell(cell);
			t3.addCell(detalle.calcularImporte().toString());
		}
		
		cell = new PdfPCell(new Phrase("Gran Total: "));
		cell.setColspan(3);
		cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
		t3.addCell(cell);
		t3.addCell(factura.getTotal().toString());
		
		document.add(t);
		document.add(t2);
		document.add(t3);
	}

}
