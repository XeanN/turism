import React from "react";
import "./newsletter.css";
import { Container, Row, Col } from "reactstrap";
import maleTourist from "../assets/images/male-tourist.png";
import { useLanguage } from "../context/LanguageContext";

const text = {
  en: {
    title: "Subscribe now to get useful traveling information.",
    placeholder: "Enter your email",
    button: "Subscribe",
    body: "Explore the world with us! 🌎🌟 Subscribe now and unlock a universe of travel tips, amazing destinations and exclusive offers. Your next adventure starts here. Don't be left out, join our traveling community today and make every moment count! ✈️🗺️",
  },
  es: {
    title: "Suscríbete ahora y recibe información útil para tu viaje.",
    placeholder: "Ingresa tu correo",
    button: "Suscribirme",
    body: "¡Explora el mundo con nosotros! 🌎🌟 Suscríbete ahora y descubre un universo de tips de viaje, destinos increíbles y ofertas exclusivas. Tu próxima aventura empieza aquí. No te quedes fuera, únete hoy a nuestra comunidad viajera y aprovecha cada momento. ✈️🗺️",
  },
};

const Newsletter = () => {
  const lang = useLanguage();
  const t = text[lang];
  return (
    <section className="newsletter">
      <Container>
        <Row>
          <Col lg="6">
            <div className="newsletter__content">
              <h2>{t.title}</h2>

              <div className="newsletter__input">
                <input type="email" placeholder={t.placeholder} />
                <button className="btn newsletter__btn">{t.button}</button>
              </div>
              <p>{t.body}</p>
            </div>
          </Col>

          <Col lg="6">
            <div className="newsletter__img">
              <img src={maleTourist} alt="Turista disfrutando su viaje con Turismo Nautico Paracas" />
            </div>
          </Col>
        </Row>
      </Container>
    </section>
  );
};

export default Newsletter;
