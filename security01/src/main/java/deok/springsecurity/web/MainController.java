package deok.springsecurity.web;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;


@Controller
@PropertySource("classpath:messages.properties")
public class MainController {

    @Value("${cp.user.name}")
    private String userName;


    @RequestMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @RequestMapping("/index")
    public String index() {
        return "index";
    }

    @RequestMapping("/deokju/index")
    public String userIndex() {
        System.out.println(userName);
        return "deokju/index";
    }

    @RequestMapping("/login")
    public String login() {
        return "login2";
    }

    @RequestMapping("/login-error")
    public String loginError(HttpSession session, Model model) {
        model.addAttribute("loginError", true);
        System.out.println(session.getAttribute("SPRING_SECURITY_LAST_EXCEPTION"));
        return "login2";
    }

}