$(function(){
	autocomplete();
});

autocomplete = function(){
	$('#buscar_producto').autocomplete({
		
		source: function(request, response) {
			let solicitud = $.ajax({
								//type:'GET'
								url: '/factura/cargar-productos/' + request.term,
								dataType: 'json',
								data: {
									term: request.term
								}
							});
				solicitud.done(function(datos) {
					response($.map(datos, function(item) {
						return {
							value:  item.id,
							label:  item.nombre,
							precio: item.precio
						};
					}));
				});
		},
		select: function(event, ui) {
			//$('#buscar_producto').val(ui.item.label);
			
			if(itemsHelper.hasProducto(ui.item.value)){
				itemsHelper.incrementarCantidad(ui.item.value, ui.item.precio);
				return false;
			}
			
			var linea = $('#plantillaItemsFactura').html();
			
			linea = linea.replace(/{ID}/g, ui.item.value);
			linea = linea.replace(/{NOMBRE}/g, ui.item.label);
			linea = linea.replace(/{PRECIO}/g, ui.item.precio);
			
			$('#cargarItemProducto tbody').append(linea);
			
			itemsHelper.calcularImporte(ui.item.value, ui.item.precio, 1);
			
			return false;
		}
	});
	
	$('form').submit(function() {
		$('#plantillaItemsFactura').remove();
	});
}



var itemsHelper = {
		calcularImporte: function(id, precio, cantidad){
			$('#totalImporte_'+id).html(parseInt(precio) * parseInt(cantidad));
			this.totalFactura(); //Actualiza gran total
		},
		hasProducto: function(id){
			var resultado = false;
			$('input[name="item_id[]"]').each(function(){
				if(parseInt(id) == parseInt($(this).val())){
					resultado = true;
				}
			});
			return resultado;
		},
		incrementarCantidad: function(id, precio){
			var cantidad = $('#cantidad_'+id).val() ? parseInt($('#cantidad_'+id).val()) : 0;
			$('#cantidad_'+id).val(++cantidad);
			this.calcularImporte(id, precio, cantidad);
		},
		eliminarProducto: function(id){
			$('#row_'+id).remove();
			this.totalFactura(); //Actualizar gran total
		},
		totalFactura: function(){
			var total = 0;
			$('span[id^="totalImporte_"]').each(function(){
				total += parseInt($((this)).html());
			});
			$('#granTotal').html(total);
		}
}