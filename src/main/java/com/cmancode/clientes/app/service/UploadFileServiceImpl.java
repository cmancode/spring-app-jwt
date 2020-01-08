package com.cmancode.clientes.app.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UploadFileServiceImpl implements IUploadFileService {

	
	private final static String UPLOADS_FOLDER = "uploads";
	
	@Override
	public void load(String fileName, MultipartFile file) throws IOException {
		Files.copy(file.getInputStream(), getPath(fileName));
	}

	@Override
	public boolean deteleFile(String fileName) {
		File archivo = getPath(fileName).toFile(); //Eliminando imagen de cliente
		if(archivo.canRead() && archivo.exists()) {
			if(archivo.delete()) {
				return true;
			}
		}
		return false;
	}
	
	public Path getPath(String fileName) {
		return Paths.get(UPLOADS_FOLDER).resolve(fileName).toAbsolutePath();
	}
	
}
