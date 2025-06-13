import React from "react";
import "./footer.css";

import { Container, Row, Col, ListGroup, ListGroupItem } from "reactstrap";
import { Link } from "react-router-dom";
import logo from "../../assets/images/logo3.png";

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

const quick__links = [
  {
    path: "/home",
    display: "Home",
  },
  {
    path: "/about",
    display: "About",
  },
  {
    path: "/tours",
    display: "Tours",
  },
];

const quick__links2 = [
  // {
  //   path: "/gallery",
  //   display: "Gallery",
  // },
  {
    path: "/login",
    display: "Login",
  },
  {
    path: "/register",
    display: "Register",
  },
];

const Footer = () => {
  const year = new Date().getFullYear();

  return (
    <footer className="footer">
      <Container>
        <Row>
          <Col lg="3">
            <div className="logo">
              <img src={logo} alt="" />
              <p>Turismo Nautico Paracas</p>

              <div className="social__links d-flex align-items-center gap-4 social-icons">
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
            </div>
          </Col>

          <Col lg="3">
            <h5 className="footer__link-title">Discover</h5>
            <ListGroup className="footer__quick-links">
              {quick__links.map((item, index) => (
                <ListGroupItem key={index} className="ps-0 border-0">
                  <Link to={item.path}>{item.display}</Link>
                </ListGroupItem>
              ))}
            </ListGroup>
          </Col>
          <Col lg="3">
            <h5 className="footer__link-title">Quick Links</h5>
            <ListGroup className="footer__quick-links">
              {quick__links2.map((item, index) => (
                <ListGroupItem key={index} className="ps-0 border-0">
                  <Link to={item.path}>{item.display}</Link>
                </ListGroupItem>
              ))}
            </ListGroup>
          </Col>
          <Col lg="3">
            <h5 className="footer__link-title">Contact</h5>
            <ListGroup className="footer__quick-links">
              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-map-pin-line"></i>
                  </span>
                  Address:
                </h6>
                <p className="mb-0">A.H.Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru</p>
              </ListGroupItem>

              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-mail-line"></i>
                  </span>
                  Email:
                </h6>
                <p className="mb-0">Turismonauticoparacas@gmail.com</p>
              </ListGroupItem>

              <ListGroupItem className="ps-0 border-0 d-flex align-items-center gap-3">
                <h6 className="mb-0 d-flex align-items-center gap-2">
                  <span>
                    <i className="ri-phone-fill"></i>
                  </span>
                  Phone:
                </h6>
                <p className="mb-0">+51 956481002</p>
              </ListGroupItem>
            </ListGroup>
          </Col>

          <Col lg="12" className="text-center pt-5">
            <p className="copyright">
              Copyright {year} by Turismo Nautico Paracas. All rights reserved.
            </p>
          </Col>
        </Row>
      </Container>
    </footer>
  );
};
export default Footer;
