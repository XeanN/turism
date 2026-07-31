import React from "react";
import "./footer.css";

import { Container, Row, Col, ListGroup, ListGroupItem } from "reactstrap";
import { Link } from "react-router-dom";
import logo from "../../assets/images/logo3.png";
import tripadvisorLogo from "../../assets/images/tripadvisor.png";
import getyourguideLogo from "../../assets/images/getyourguide.png";
import { useLanguage, withLang } from "../../context/LanguageContext";


const phoneNumber = +51956481002;
const whatsappMessage =
  "Hello, Welcome to Turismo Nautico Paracas, how can I help you?";
const whatsappLink = `https://wa.me/${phoneNumber}?text=${encodeURIComponent(
  whatsappMessage
)}`;

const facebookLink =
  "https://www.facebook.com/TurismoNauticoParacas?mibextid=ZbWKwL";
const instagramLink = "https://www.instagram.com/southamericanssecrets/?hl=es";
const youtubeLink = "https://www.youtube.com/@luciohancco3237";

const quick__links = {
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

const quick__links2 = {
  en: [
    { path: "/login", display: "Login" },
    { path: "/register", display: "Register" },
  ],
  es: [
    { path: "/login", display: "Iniciar sesión" },
    { path: "/register", display: "Registrarse" },
  ],
};

const footerText = {
  en: { discover: "Discover", quickLinks: "Quick Links", contact: "Contact", address: "Address:", email: "Email:", phone: "Phone:", rights: "All rights reserved." },
  es: { discover: "Descubre", quickLinks: "Enlaces Rápidos", contact: "Contacto", address: "Dirección:", email: "Correo:", phone: "Teléfono:", rights: "Todos los derechos reservados." },
};

const Footer = () => {
  const year = new Date().getFullYear();
  const lang = useLanguage();
  const t = footerText[lang];

  return (
    <footer className="footer">
      <Container>
        <Row>
          <Col lg="3">
            <div className="logo">
              <Link to={withLang("/home", lang)}>
                <img src={logo} alt="logo" />
              </Link>
              <p>Turismo Nautico Paracas</p>

              <div className="social__links d-flex align-items-center gap-2 social-icons">
                <span>
                  <a
                    href={whatsappLink}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <i className="ri-whatsapp-line"></i>
                  </a>
                </span>

                <span>
                  <a
                    href={facebookLink}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <i className="ri-facebook-circle-line"></i>
                  </a>
                </span>

                <span>
                  <a
                    href={instagramLink}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <i className="ri-instagram-line"></i>
                  </a>
                </span>

                <span>
                  <a
                    href={youtubeLink}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <i className="ri-youtube-line"></i>
                  </a>
                </span>
              </div>
              <div className="external__logos d-flex align-items-center gap-3 mt-3">
                <a href="https://www.tripadvisor.com.pe/" target="_blank" rel="noreferrer">
                  <img
                    src={tripadvisorLogo}
                    alt="Tripadvisor"
                    className="external-logo-footer"
                  />
                </a>
                <a href="https://www.getyourguide.com/" target="_blank" rel="noreferrer">
                  <img
                    src={getyourguideLogo}
                    alt="GetYourGuide"
                    className="external-logo-footer"
                  />
                </a>
              </div>

            </div>
          </Col>

          <Col lg="3">
            <h5 className="footer__link-title">{t.discover}</h5>
            <ListGroup className="footer__quick-links">
              {quick__links[lang].map((item, index) => (
                <ListGroupItem key={index} className="ps-0 border-0">
                  <Link to={withLang(item.path, lang)}>{item.display}</Link>
                </ListGroupItem>
              ))}
            </ListGroup>
          </Col>
          <Col lg="3">
            <h5 className="footer__link-title">{t.quickLinks}</h5>
            <ListGroup className="footer__quick-links">
              {quick__links2[lang].map((item, index) => (
                <ListGroupItem key={index} className="ps-0 border-0">
                  <Link to={withLang(item.path, lang)}>{item.display}</Link>
                </ListGroupItem>
              ))}
            </ListGroup>
          </Col>
          <Col lg="3">
            <h5 className="footer__link-title">{t.contact}</h5>
            <ListGroup className="footer__quick-links">
              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-map-pin-line"></i>
                  </span>
                  {t.address}
                </h6>
                <p className="mb-0">A.H.Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru</p>
              </ListGroupItem>

              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-mail-line"></i>
                  </span>
                  {t.email}
                </h6>
                <p className="mb-0">Turismonauticoparacas@gmail.com</p>
              </ListGroupItem>

              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-phone-fill"></i>
                  </span>
                  {t.phone}
                </h6>
                <p className="mb-0">+51 956481002</p>
              </ListGroupItem>
            </ListGroup>
          </Col>

          <Col lg="12" className="text-center pt-5">
            <p className="copyright">
              Copyright {year} by Turismo Nautico Paracas. {t.rights}
            </p>
          </Col>
        </Row>
      </Container>
    </footer>
  );
};
export default Footer;
