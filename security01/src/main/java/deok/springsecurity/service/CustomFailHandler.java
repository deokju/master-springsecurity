package deok.springsecurity.service;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomFailHandler implements AuthenticationFailureHandler {

    private String loginIdName;         // 로그인 id값이 들어오는 input 태그 name
    private String loginPasswdName;     // 로그인 password 값이 들어오는 input 태그 name
    private String loginRedirectName;   // 로그인 성공시 redirect 할 URL이 지정되어 있는 input 태그 name
    private String exceptionMsgName;    // 예외 메세지를 request의 Attribute에 저장할 때 사용될 key 값
    private String defaultFailureUrl;   // 화면에 보여줄 URL(로그인 화면)

    public CustomFailHandler() {
        this.loginIdName = "username";
        this.loginPasswdName="password";
        this.loginRedirectName="loginRedirect";
        this.exceptionMsgName="securityexceptionmsg";
        this.defaultFailureUrl="/login";
    }


    @Override
    public void onAuthenticationFailure(HttpServletRequest  request,
                                        HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        //Request 객체의 attribute에 사용자가 실패시 입력했던 로그인 ID와 비밀번호를 저장해두어 로그인 페이지에서 이를 접근하도록 한다.
        String loginId       = request.getParameter(loginIdName);
        String loginPassword = request.getParameter(loginPasswdName);
        String loginRedirect = request.getParameter(loginRedirectName);

        request.setAttribute(loginIdName,       loginId);
        request.setAttribute(loginPasswdName,   loginPassword);
        request.setAttribute(loginRedirectName, loginRedirect);

        request.setAttribute(exceptionMsgName, e.getMessage());
        request.getRequestDispatcher(defaultFailureUrl).forward(request, response);

    }
}
