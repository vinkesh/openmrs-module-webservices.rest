package org.openmrs.module.webservices.rest.web.filter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Context;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

public class TwoFactorAuthenticationFilter implements Filter {
	
	protected final Log log = LogFactory.getLog(getClass());
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException,
	        ServletException {
		// skip if the session has timed out, we're already authenticated, or it's not an HTTP request
		if (request instanceof HttpServletRequest) {
			MutableHttpServletRequest httpRequest = new MutableHttpServletRequest((HttpServletRequest) request);
			if (!Context.isAuthenticated()) {
				String authCredentials = httpRequest.getHeader("Authorization");
				if (authCredentials == null) {
					filterChain.doFilter(request, response);
					return;
				}
				Object authOne = httpRequest.getSession().getAttribute("authOne");
				if (authOne == null) {
					if (firstLevelAuth(authCredentials)) {
						httpRequest.getSession().setAttribute("authOne", true);
						
						HttpServletResponse httpServletResponse = (HttpServletResponse) response;
						httpServletResponse.setStatus(204);
						return;
					}
				}
				
				if (authOne != null) {
					if (validateOTP(authCredentials) == true) {
						httpRequest.getSession().removeAttribute("authOne");
						try {
							authCredentials = authCredentials.substring(6); // remove the leading "Basic "
							String decoded = new String(Base64.decodeBase64(authCredentials), Charset.forName("UTF-8"));
							String[] userAndPass = decoded.split(":");
							Context.authenticate(userAndPass[0], userAndPass[1]);
						}
						catch (Exception ex) {
							// This filter never stops execution. If the user failed to
							// authenticate, that will be caught later.
						}
						
					}
				}
			}
			
		}
		
		// continue with the filter chain in all circumstances
		filterChain.doFilter(request, response);
	}
	
	private boolean validateOTP(String otp) {
		return true;
	}
	
	private boolean firstLevelAuth(String userAndPas) throws IOException {
		return true;
	}
	
	@Override
	public void destroy() {
		
	}
}
