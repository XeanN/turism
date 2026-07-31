import React, { useRef, useEffect, useContext } from "react";
import { Container, Row, Button } from "reactstrap";
import { NavLink, Link, useNavigate, useLocation } from "react-router-dom";

import logo from "../../assets/images/logo3.png";
import tripadvisorLogo from "../../assets/images/tripadvisor.png";
import getyourguideLogo from "../../assets/images/getyourguide.png";
import "./header.css";

import { AuthContext } from "../../context/AuthContext";
import { useLanguage, withLang } from "../../context/LanguageContext";

const navLinksByLang = {
  en: [
    { path: "/home", display: "Home" },
    { path: "/about", display: "About" },
    { path: "/tours", display: "Tours" },
    { path: "/blogs", display: "Blogs" },
    { path: "/contact", display: "Contact" },
    { path: "/gallery", display: "Gallery" },
  ],
  es: [
    { path: "/home", display: "Inicio" },
    { path: "/about", display: "Nosotros" },
    { path: "/tours", display: "Tours" },
    { path: "/blogs", display: "Blog" },
    { path: "/contact", display: "Contacto" },
    { path: "/gallery", display: "Galería" },
  ],
};

const headerText = {
  en: { login: "Login", register: "Register", logout: "Logout" },
  es: { login: "Iniciar sesión", register: "Registrarse", logout: "Cerrar sesión" },
};

const Header = () => {
  const headerRef = useRef(null);
  const menuRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { user, dispatch } = useContext(AuthContext);
  const lang = useLanguage();
  const nav__links = navLinksByLang[lang];
  const t = headerText[lang];

  // path actual sin el prefijo /es, para armar el link a cada idioma
  const pathWithoutLang =
    lang === "es" ? location.pathname.replace(/^\/es/, "") || "/" : location.pathname;
  const enHref = pathWithoutLang;
  const esHref = withLang(pathWithoutLang, "es");

  const logout = () => {
    dispatch({ type: "LOGOUT" });
    //TODO:FALTA PROBAR RESULTADOS
    //localStorage.removeItem('user'); // Limpia el valor del usuario en localStorage
    navigate(withLang("/", lang));
  };

  const stickyHeaderFunc = () => {
    if (
      document.body.scrollTop > 80 ||
      document.documentElement.scrollTop > 80
    ) {
      headerRef.current.classList.add("sticky__header");
    } else {
      headerRef.current.classList.remove("sticky__header");
    }
  };

  useEffect(() => {
    window.addEventListener("scroll", stickyHeaderFunc);

    return () => {
      window.removeEventListener("scroll", stickyHeaderFunc);
    };
  }, []);

  const toggleMenu = () => menuRef.current.classList.toggle("show__menu");

  return (
    <header className="header" ref={headerRef}>
      <Container>
        <Row>
          <div className="nav__wrapper d-flex align-items-center justify-content-between">
            {/*==================logo================ */}
            <div className="logo">
              <Link to={withLang("/home", lang)}>
                <img src={logo} alt="logo" />
              </Link>
            </div>
            {/*==================endLogo================ */}
            {/*==================menu Start================ */}
            <div className="navigation" ref={menuRef} onClick={toggleMenu}>
              <ul className="menu d-flex align-items-center gap-2">
                {nav__links.map((item, index) => (
                  <li className="nav__item" key={index}>
                    <NavLink
                      to={withLang(item.path, lang)}
                      className={(navClass) =>
                        navClass.isActive ? "active__link" : ""
                      }
                    >
                      {item.display}
                    </NavLink>
                  </li>
                  ))}
                  <li className="nav__item lang__switch">
                    <Link
                      to={enHref}
                      className={lang === "en" ? "active__link" : ""}
                      onClick={(e) => e.stopPropagation()}
                    >
                      EN
                    </Link>
                    {" / "}
                    <Link
                      to={esHref}
                      className={lang === "es" ? "active__link" : ""}
                      onClick={(e) => e.stopPropagation()}
                    >
                      ES
                    </Link>
                  </li>
                  <li className="nav__item external__logos">
                    <a href="https://www.tripadvisor.com/Attraction_Review-g445063-d6387633-Reviews-South_Americans_Secrets-Paracas_Ica_Region.html" target="_blank" rel="noreferrer">
                      <img src={tripadvisorLogo} alt="Tripadvisor" className="external-logo" />
                    </a>
                    <a href="https://www.getyourguide.es/south-americans-secrets-eirl-s353664/" target="_blank" rel="noreferrer">
                      <img src={getyourguideLogo} alt="GetYourGuide" className="external-logo" />
                    </a>
                  </li>
                
              </ul>
            </div>
            {/*==================menu End================ */}

            <div className="nav__right d-flex align-items-center gap-4">
              <div className="nav__btns d-flex align-items-center gap-4">
                {user ? (
                  <>
                    <h5 className="mb-0">{user.username}</h5>
                    <Button className="btn btn_dark" onClick={logout}>
                      {t.logout}
                    </Button>
                  </>
                ) : (
                  <>
                    <Button className="btn secondary__btn">
                      <Link to={withLang("/login", lang)}>{t.login}</Link>
                    </Button>
                    <Button className="btn primary__btn">
                      <Link to={withLang("/register", lang)}>{t.register}</Link>
                    </Button>
                  </>
                )}
              </div>
              <span className="mobile__menu" onClick={toggleMenu}>
                <i className="ri-menu-line"></i>
              </span>
            </div>
          </div>
        </Row>
      </Container>
    </header>
  );
};
export default Header;
