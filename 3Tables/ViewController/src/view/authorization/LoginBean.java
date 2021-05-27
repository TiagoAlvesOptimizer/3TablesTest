package view.authorization;

import weblogic.security.URLCallbackHandler;

import weblogic.servlet.security.ServletAuthentication;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import javax.servlet.http.HttpServletRequest;

import weblogic.security.URLCallbackHandler;

import weblogic.servlet.security.ServletAuthentication;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;

import java.io.IOException;

import javax.faces.context.ExternalContext;

import javax.servlet.http.HttpSession;

public class LoginBean
{
  public LoginBean()
  {
  }

  private String _username;
  private String _password;

  public void setUsername(String _username)
  {
    this._username = _username;
  }

  public String getUsername()
  {
    return _username;
  }

  public void setPassword(String _password)
  {
    this._password = _password;
  }

  public String getPassword()
  {
    return _password;
  }

  public String doLogin()
  {
    System.out.println(_username + " | " + _password);
    String un = _username;
    byte[] pw = _password.getBytes();
    FacesContext ctx = FacesContext.getCurrentInstance();
    HttpServletRequest request = (HttpServletRequest) ctx.getExternalContext().getRequest();
    try
    {
      CallbackHandler handler = new URLCallbackHandler(un, pw);
      Subject mySubj = weblogic.security
                               .services
                               .Authentication
                               .login(handler);
      weblogic.servlet
              .security
              .ServletAuthentication
              .runAs(mySubj, request);
      ServletAuthentication.generateNewSessionID(request);
      String loginURL = "faces/main.jsf";
      sendForward(loginURL);
    }
    catch (FailedLoginException fle)
    {
      FacesMessage msg =
        new FacesMessage(FacesMessage.SEVERITY_ERROR, "Incorrect Username or Password",
                         "An incorrect Username or Password" + " was specified");
      ctx.addMessage(null, msg);
      setPassword(null);
    }
    catch (LoginException le)
    {
      reportUnexpectedLoginError("LoginException", le);
    }
    return null;
  }

  private void reportUnexpectedLoginError(String errType, Exception e)
  {
    FacesMessage msg =
      new FacesMessage(FacesMessage.SEVERITY_ERROR, "Unexpected errorduring login",
                       "Unexpected error during login (" + errType + "), please consult logs for detail");
    FacesContext.getCurrentInstance().addMessage(null, msg);
    FacesContext.getCurrentInstance().renderResponse();
  }

  private void sendForward(String forwardUrl)
  {
    FacesContext ctx = FacesContext.getCurrentInstance();
    try
    {
      ctx.getExternalContext().redirect(forwardUrl);
    }
    catch (IOException ie)
    {
      reportUnexpectedLoginError("IOException", ie);
    }
    ctx.responseComplete();
  }

  public String onLogout()
  {
    FacesContext fctx = FacesContext.getCurrentInstance();
    ExternalContext ectx = fctx.getExternalContext();
    String url = ectx.getRequestContextPath() + "/adfAuthentication?logout=true&end_url=/faces/login.jsf";

    HttpSession session = (HttpSession) ectx.getSession(false);
    session.invalidate();

    HttpServletRequest request = (HttpServletRequest) ectx.getRequest();
    ServletAuthentication.logout(request);
    ServletAuthentication.invalidateAll(request);
    ServletAuthentication.killCookie(request);

    try
    {
      ectx.redirect(url);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    fctx.responseComplete();

    return null;
  }
}
