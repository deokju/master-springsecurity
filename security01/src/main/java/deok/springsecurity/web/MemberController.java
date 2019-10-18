package deok.springsecurity.web;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/member/")
public class MemberController {


    @GetMapping("info")
    public String info() {
        return "member/info";
    }

}