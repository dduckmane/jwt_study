package com.cos.jwt.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        //토큰: 코스라고 가정
        String headerAuth = req.getHeader("Authorization");
        System.out.println("필터3");
        System.out.println("POST요청됨");
        if(headerAuth.equals("cos")){
            chain.doFilter(req,res);
        }else {
            PrintWriter out=res.getWriter();
            out.println("인증안됨");
        }

    }
}
