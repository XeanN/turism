import React from "react";
import { Container, Row, Col, Button } from "reactstrap";
import { Link } from "react-router-dom";
import "../styles/thank-you.css";
import { useLanguage, withLang } from "../context/LanguageContext";

const text = {
  en: { title: "Thank You", subtitle: "your tour is reserved.", back: "Back to Home" },
  es: { title: "¡Gracias!", subtitle: "tu tour está reservado.", back: "Volver al Inicio" },
};

const ThankYou = () => {
  const lang = useLanguage();
  const t = text[lang];
  return (
    <section>
      <Container>
        <Row>
          <Col lg="12" className="pt-5 text-center">
            <div className="thank__you">
              <span>
                <i className="ri-checkbox-circle-line"></i>
              </span>
              <h1 className="mb-3 fw-semibold">{t.title}</h1>
              <h3 className="mb-4">{t.subtitle}</h3>

              <Button className="btn primary__btn w-25">
                <Link to={withLang("/home", lang)}>{t.back}</Link>
              </Button>
            </div>
          </Col>
        </Row>
      </Container>
    </section>
  );
};

export default ThankYou;
