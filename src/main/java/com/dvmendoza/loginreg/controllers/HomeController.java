package com.dvmendoza.loginreg.controllers;


import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.dvmendoza.loginreg.models.LoginUser;
import com.dvmendoza.loginreg.models.User;
import com.dvmendoza.loginreg.services.UserService;

@Controller
public class HomeController {
	
	@Autowired
	private UserService service;
	
	@GetMapping("/")
	public String index(Model model) {
		model.addAttribute("newUser", new User());
		model.addAttribute("newLogin", new LoginUser());
		return "index.jsp";
	}
	
    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("newUser") User newUser,
                           BindingResult result, Model model, HttpSession session) {
        User registeredUser = service.register(newUser, result);
        if(result.hasErrors()) {
            model.addAttribute("newLogin", new LoginUser());
            return "index.jsp";
        }
        session.setAttribute("userId", registeredUser.getId());
        return "redirect:/home";
    }
    
    @PostMapping("/login")
    public String login(@Valid @ModelAttribute("newLogin") LoginUser newLogin,
                        BindingResult result, Model model, HttpSession session) {
        User user = service.login(newLogin, result);
        if(result.hasErrors()) {
            model.addAttribute("newUser", new User());
            return "index.jsp";
        }
        session.setAttribute("userId", user.getId());
        return "redirect:/home";
    }
    
    @GetMapping("/logout")
    String logout(HttpSession session) {
    	session.removeAttribute("userId");
    	return "redirect:/";
    }
    
    @GetMapping("/home")
    String home(HttpSession session, Model model) {
        model.addAttribute("user", service.getOne((Long) session.getAttribute("userId")));
        return "home.jsp";
    }
    
 

}
