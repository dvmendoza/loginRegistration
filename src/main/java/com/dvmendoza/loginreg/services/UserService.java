package com.dvmendoza.loginreg.services;

import java.util.List;
import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;

import com.dvmendoza.loginreg.models.LoginUser;
import com.dvmendoza.loginreg.models.User;
import com.dvmendoza.loginreg.repositories.UserRepository;

@Service
public class UserService {
    @Autowired
    UserRepository repo;

    public User register(User user, BindingResult result) {
        if (repo.findByEmail(user.getEmail()).isPresent()) {
            result.rejectValue("email", "Taken", "Email is already in use");
        }
        if (!user.getPassword().equals(user.getConfirm())) {
            result.rejectValue("confirm", "Matches", "Passwords must match");
        }
        if (result.hasErrors()) {
            return null;
        }
        String hashed = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());
        user.setPassword(hashed);
        repo.save(user);
        return user;
    }
    public User login(LoginUser newLoginObject, BindingResult result) {
        User userInDB = repo.findByEmail(newLoginObject.getEmail()).get();
        if (!repo.findByEmail(newLoginObject.getEmail()).isPresent()) {
            result.rejectValue("email", "Unknown", "Invalid Email");
        }
        if(!BCrypt.checkpw(newLoginObject.getPassword(), userInDB.getPassword())) {
            result.rejectValue("password", "Matches", "Invalid Password");
        }
        if (result.hasErrors()) {
            return null;
        }
        return userInDB;
    }
    // CRUD Methods
    public List<User> getAll() {
        return repo.findAll();
    }
    public User getOne(Long id) {
        Optional<User> user = repo.findById(id);
        return user.orElse(null);
    }
    public void update(User user) { repo.save(user); }
    public void delete(Long id) {
        repo.deleteById(id);
    }
}