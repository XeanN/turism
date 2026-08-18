import React, { useState, useContext } from "react";
import { Helmet } from "react-helmet";
import { Container, Row, Col, Form, FormGroup, Button } from "reactstrap";
import { Link, useNavigate } from "react-router-dom";
import "../styles/login.css";

import registerImg from "../assets/images/register.png";
import userIcon from "../assets/images/user.png";

import { AuthContext } from "./../context/AuthContext";
import { BASE_URL } from "./../utils/config";
import { useLanguage, withLang } from "./../context/LanguageContext";

const text = {
  en: { title: "Register", username: "Username", email: "Email", password: "Password", submit: "Create Account", haveAccount: "Already have an account?", login: "Login" },
  es: { title: "Registrarse", username: "Usuario", email: "Correo", password: "Contraseña", submit: "Crear Cuenta", haveAccount: "¿Ya tienes una cuenta?", login: "Iniciar sesión" },
};

const Register = () => {
  const [credentials, setCredentials] = useState({
    username: undefined,
    email: undefined,
    password: undefined,
  });

  const { dispatch } = useContext(AuthContext);
  const navigate = useNavigate();
  const lang = useLanguage();
  const t = text[lang];

  const handleChange = (e) => {
    setCredentials((prev) => ({ ...prev, [e.target.id]: e.target.value }));
  };

  const handleClick = async (e) => {
    e.preventDefault();

    try {
      const formData = new FormData();
      formData.append("username", credentials.username);
      formData.append("email", credentials.email);
      formData.append("password", credentials.password);

      const res = await fetch(`${BASE_URL}/usuario/register`, {
        method: "post",
        credentials: "include",
        body: formData,
      });

      const result = await res.json();

      if (result.success) {
        dispatch({ type: "REGISTER_SUCCESS" });
        navigate(withLang("/login", lang));
      } else {
        return alert(result.message);
      }
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <section>
      <Helmet>
        <meta name="robots" content="noindex, follow" />
      </Helmet>
      <Container>
        <Row>
          <Col lg="8" className="m-auto">
            <div className="login__container d-flex justify-content-between">
              <div className="login__img">
                <img src={registerImg} alt="Ilustración de registro de usuario" />
              </div>

              <div className="login__form">
                <div className="user">
                  <img src={userIcon} alt="Ícono de usuario" />
                </div>
                <h2>{t.title}</h2>

                <Form onSubmit={handleClick}>
                  <FormGroup>
                    <input
                      type="text"
                      placeholder={t.username}
                      required
                      id="username"
                      onChange={handleChange}
                    />
                  </FormGroup>
                  <FormGroup>
                    <input
                      type="email"
                      placeholder={t.email}
                      required
                      id="email"
                      onChange={handleChange}
                    />
                  </FormGroup>
                  <FormGroup>
                    <input
                      type="password"
                      placeholder={t.password}
                      required
                      id="password"
                      onChange={handleChange}
                    />
                  </FormGroup>
                  <Button
                    className="btn secondary__btn auth__btn"
                    type="submit"
                  >
                    {t.submit}
                  </Button>
                </Form>
                <p>
                  {t.haveAccount} <Link to={withLang("/login", lang)}>{t.login}</Link>
                </p>
              </div>
            </div>
          </Col>
        </Row>
      </Container>
    </section>
  );
};

export default Register;
