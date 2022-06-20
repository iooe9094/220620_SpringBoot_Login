package com.example.taegyungsi.service;

import com.example.taegyungsi.dao.TutorialDao;
import com.example.taegyungsi.model.Tutorial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class TutorialServiceImpl implements TutorialService {

	@Autowired
	private TutorialDao tutorialDao;

	Logger logger = LoggerFactory.getLogger(this.getClass());

	@Override
	public Optional<Tutorial> findById(long id) {
		return tutorialDao.findById(id);
	}

	@Override
	public List<Tutorial> findByPublished(String published) {
		return tutorialDao.findByPublished(published);
	}

	@Override
	public List<Tutorial> findByTitleContaining(String title) {
		List<Tutorial> tutorials = Collections.emptyList();

		if (title == null)
			tutorials = tutorialDao.findAll();
		else
			tutorials = tutorialDao.findByTitleContaining(title);

		return tutorials;
	}

	@Override
	public List<Tutorial> findAll() {

		return tutorialDao.findAll();
	}

	@Override
	public boolean save(Tutorial tutorial) {
		int queryResult = 0;

		logger.info("tutorial {}", tutorial);

		if (tutorial.getId() == null) {
			logger.info("tutorial.getId() {}", tutorial.getId());
			queryResult = tutorialDao.insertTutorial(tutorial);
			logger.info("queryResult {}", queryResult);
		} else {
			queryResult = tutorialDao.updateTutorial(tutorial);
		}

		return (queryResult >= 1) ? true : false;
	}

	@Override
	public boolean deleteById(Long id) {
		int queryResult = 0;

		queryResult = tutorialDao.deleteById(id);

		return (queryResult >= 1) ? true : false;
	}

	@Override
	public boolean deleteAll() {
		int queryResult = 0;

		queryResult = tutorialDao.deleteAll();

		return (queryResult >= 1) ? true : false;
	}
}
