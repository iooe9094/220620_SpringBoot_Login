package com.example.taegyungsi.dao;

import com.example.taegyungsi.model.Tutorial;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Optional;

@Mapper
public interface TutorialDao {

	public List<Tutorial> findByPublished(String published);
	public List<Tutorial> findByTitleContaining(String title);
	public List<Tutorial> findAll();

	public Optional<Tutorial> findById(Long id);

	public int insertTutorial(Tutorial tutorial);

	public int updateTutorial(Tutorial tutorial);

	public int deleteById(Long id);

	public int deleteAll();

}