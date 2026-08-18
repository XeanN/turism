import React, { useState, useContext } from "react";
import { Helmet } from "react-helmet";
import { Container, Row, Col, Form, FormGroup, Button } from "reactstrap";
import { Link, useNavigate } from "react-router-dom";
import "../styles/login.css";

import loginImg from "../assets/images/login.png";
import userIcon from "../assets/images/user.png";
import { AuthContext } from "./../context/AuthContext";
import { BASE_URL } from "./../utils/config";
import { useLanguage, withLang } from "./../context/LanguageContext";

const text = {
  en: { title: "Login", email: "Email", password: "Password", submit: "Login", noAccount: "Don't have an account?", create: "Create" },
  es: { title: "Iniciar sesión", email: "Correo", password: "Contraseña", submit: "Iniciar sesión", noAccount: "¿No tienes una cuenta?", create: "Crear" },
};

const Login = () => {
  const [credentials, setCredentials] = useState({
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

    dispatch({ type: "LOGIN_START" });
    try {
      const formData = new FormData();
      formData.append("email", credentials.email);
      formData.append("password", credentials.password);

      const res = await fetch(`${BASE_URL}/usuario/login`, {
        method: "post",
        credentials: "include",
        body: formData,
      });

      // Aquí maneja la respuesta como lo haces normalmente

      const result = await res.json();

      if (result.success) {
        dispatch({ type: "LOGIN_SUCCESS", payload: result.data });
        navigate(withLang("/", lang));
      } else {
        return alert(result.message);
      }
    } catch (err) {
      dispatch({ type: "LOGIN_FAILURE", payload: err.message });
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
                <img src={loginImg} alt="Ilustración de inicio de sesión" />
              </div>

              <div className="login__form">
                <div className="user">
                  <img src={userIcon} alt="Ícono de usuario" />
                </div>
                <h2>{t.title}</h2>

                <Form onSubmit={handleClick}>
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
                  {t.noAccount} <Link to={withLang("/register", lang)}>{t.create}</Link>
                </p>
              </div>
            </div>
          </Col>
        </Row>
      </Container>
    </section>
  );
};

export default Login;
