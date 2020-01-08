package com.cmancode.clientes.app.service;

import java.io.IOException;

import org.springframework.web.multipart.MultipartFile;

public interface IUploadFileService {
	
	public void load(String fileName, MultipartFile file) throws IOException;
	public boolean deteleFile(String fileName);
	
}
