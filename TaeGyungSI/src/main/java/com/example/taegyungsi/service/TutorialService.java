package com.example.taegyungsi.service;

import com.example.taegyungsi.model.Tutorial;

import java.util.List;
import java.util.Optional;

public interface TutorialService {

	public Optional<Tutorial> findById(long id);
	public List<Tutorial> findByPublished(String published);
	public List<Tutorial> findByTitleContaining(String title);

	public List<Tutorial> findAll();

	public boolean save(Tutorial tutorial);

	public boolean deleteById(Long id);

	public boolean deleteAll();

}
