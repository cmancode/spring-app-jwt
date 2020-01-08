INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Carlos Alberto', 'Mantilla', 'Berdugo', 'cmantillab@sena.edu.co', '2017-12-10');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Carlos José', 'Martinez', 'Santiago', 'cmantinezs@gmail.com', '2017-12-01');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Camilo José', 'Martinez', 'Brocero', 'cbrochero@gmail.com', '1997-09-01');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'José José', 'Santiago', 'Santiago', 'jsantiago@gmail.com', '1991-10-12');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Elkin José', 'De avila', 'Mantilla', 'eklin493@gmail.com', '1984-09-16');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Santiago Andrés', 'Martinez', 'Cotes', 'das@gmail.com', '1998-12-12');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Pedro Luis', 'Cotes', 'Brito', 'pcotes@gmail.com', '1992-07-12');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Will Camilo', 'Andrades', 'Pertúz', 'wandrades@gmail.com', '1999-01-12');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Patricia Margarita', 'Terán', 'Saenz', 'pteran@gmail.com', '1978-08-07');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Efrain Camilo', 'Manrique', 'Perez', 'emanrique@gmail.com', '1965-12-01');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Esteban Camilo', 'Molsalve', 'Americo', 'emolsalve@gmail.com', '1965-12-01');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Kelly Jhoana', 'Martinez', 'Mantilla', 'kk@gmail.com', '1996-10-12');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Eduardo Davin', 'Morrinson', 'Mantilla', 'emm@gmail.com', '1980-07-09');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Elizabeth María', 'Morrinson', 'Mantilla', 'emm@gmail.com', '1980-07-09');
INSERT INTO clientes (id, nombres, p_apellido, s_apellido, correo, fecha_nacimiento) VALUES (NULL, 'Eliana', 'Morrinson', 'Mantilla', 'emm@gmail.com', '1980-07-09');

INSERT INTO productos(id, fecha_creacion, nombre, precio) VALUES (NULL,'2020-01-02','COMPUTADORA ACER',2500000);
INSERT INTO productos(id, fecha_creacion, nombre, precio) VALUES (NULL,'2020-01-02','COMPUTADORA HP',2500000);
INSERT INTO productos(id, fecha_creacion, nombre, precio) VALUES (NULL,'2020-01-02','LAVADORA LG',500000);
INSERT INTO productos(id, fecha_creacion, nombre, precio) VALUES (NULL,'2020-01-02','TV SAMSUNG 42" UHD',2700000);

INSERT INTO users(id, enabled, password, username) VALUES (NULL, 1,'$2a$10$vPrzc2TLH2WXZI.N9gGZ0eACE.YK510NeHSYFFqSlS6G1SE0TCaSK','mantilla');
INSERT INTO users(id, enabled, password, username) VALUES (NULL, 1,'$2a$10$mTJg8H6nDIujwwmrxRz/BeLnP5HxmeJqx14Tp4K2mQxdPx6Y4QX4q','tatiana');

INSERT INTO authorities(id, authority, user_id) VALUES (NULL, 'ROLE_USER',2);
INSERT INTO authorities(id, authority, user_id) VALUES (NULL, 'ROLE_ADMIN',1);
INSERT INTO authorities(id, authority, user_id) VALUES (NULL, 'ROLE_USER',1);

INSERT INTO facturas(id, descripcion, fecha, observacion, cliente_id) VALUES (NULL,'COMPRA DE PC','2020-01-02','TODO OK OK',1);
INSERT INTO detalles_facturas(id, cantidad, producto_id, factura_id) VALUES (NULL,1,1,1);
