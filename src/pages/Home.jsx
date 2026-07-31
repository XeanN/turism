import React, { useState, useEffect } from "react";
import { Helmet } from "react-helmet";
import "../styles/home.css";

import { Container, Row, Col } from "reactstrap";
//import heroImg from "../assets/images/machu_picchu_main.png";
//import heroImg02 from "../assets/images/hero-img02.jpg";
//import heroVideo from "../assets/images/hero-video.mp4";
//import worldImg from "../assets/images/world.png";
import experienceImg from "../assets/images/nuevoImage.jpg";
//import heroVideo2 from "../assets/images/yates.mp4";
import slider1 from "../assets/images/slider1_1268x738.jpg";
import slider2 from "../assets/images/slider2_1268x738.jpg";
import slider3 from "../assets/images/slider3_1268x738.jpg";
import slider4 from "../assets/images/slider4_1268x738.jpg";
import slider5 from "../assets/images/slider5_1268x738.jpg";
import Subtitle from "./../shared/Subtitle";

//import SearchBar from "../shared/SearchBar";
//import ServiceList from "../services/ServiceList";
import FeaturedTourList from "../components/Featured-tours/FeaturedTourList";
import MasonryImagesGallery from "../components/Image-gallery/MasonryImagesGallery";
import Testimonial from "../components/Testimonial/Testimonial";
import Newsletter from "../shared/Newsletter";
import { useLanguage } from "../context/LanguageContext";

const text = {
  en: {
    metaTitle: "Turismo Nautico Paracas | Tours to Ballestas Islands, Reserve and Nazca",
    metaDescription:
      "Tour agency in Paracas: Ballestas Islands, Paracas National Reserve, sandboarding in Huacachina, private yachts and Nazca Lines flights.",
    smallText: "south Perú",
    heroTitle: "Turismo Nautico Paracas",
    explore: "Explore",
    featuredTitle: "Our featured tours",
    sailWithUs: "Sail With Us",
    experienceTitle: (
      <>
        With our all experience <br /> we will serve you
      </>
    ),
    experienceText: (
      <>
        Turismo Nautico Paracas is a company focused on tourism and
        <br />
        founded by expert guides of Peru.
      </>
    ),
    trips: "Successful trip",
    clients: "Regular clients",
    years: "Years experience",
    galleryLabel: "Gallery",
    galleryTitle: "Visit our customers tour gallery",
    clientsLabel: "Clients",
    testimonialTitle: "Discover What Our Clients Have to Say",
  },
  es: {
    metaTitle: "Turismo Nautico Paracas | Tours en Islas Ballestas, Reserva y Nazca",
    metaDescription:
      "Agencia de turismo en Paracas: tours a Islas Ballestas, Reserva Nacional de Paracas, sandboarding en Huacachina, yates privados y sobrevuelo a las Líneas de Nazca.",
    smallText: "sur del Perú",
    heroTitle: "Turismo Nautico Paracas",
    explore: "Explora",
    featuredTitle: "Nuestros tours destacados",
    sailWithUs: "Navega con Nosotros",
    experienceTitle: (
      <>
        Con toda nuestra experiencia <br /> te vamos a atender
      </>
    ),
    experienceText: (
      <>
        Turismo Nautico Paracas es una empresa enfocada en el turismo
        <br />y fundada por guías expertos del Perú.
      </>
    ),
    trips: "Viajes exitosos",
    clients: "Clientes recurrentes",
    years: "Años de experiencia",
    galleryLabel: "Galería",
    galleryTitle: "Visita la galería de tours de nuestros clientes",
    clientsLabel: "Clientes",
    testimonialTitle: "Descubre lo que dicen nuestros clientes",
  },
};

const Home = () => {
  const lang = useLanguage();
  const t = text[lang];
  const canonicalUrl =
    lang === "es"
      ? "https://turismonauticoparacas.com/es/home"
      : "https://turismonauticoparacas.com/home";
  const sliderImages = [slider1, slider2, slider3, slider4, slider5];
  const [currentIndex, setCurrentIndex] = useState(0);

  // Auto-slide
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentIndex((prevIndex) =>
        prevIndex === sliderImages.length - 1 ? 0 : prevIndex + 1
      );
    }, 5000);
    return () => clearInterval(interval);
  }, [sliderImages.length]);

  const handleDotClick = (index) => {
    setCurrentIndex(index);
  };

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TravelAgency",
    name: "Turismo Nautico Paracas",
    image: "https://turismonauticoparacas.com/extras.png",
    url: canonicalUrl,
    telephone: "+51-956-481-002",
    address: {
      "@type": "PostalAddress",
      streetAddress: 'A.H. Alberto Tataje Muñoz Mz "C" Lote 2',
      addressLocality: "Paracas",
      addressCountry: "PE",
    },
    geo: {
      "@type": "GeoCoordinates",
      latitude: -13.831346219530838,
      longitude: -76.24684347399574,
    },
    hasMap:
      "https://www.google.com/maps/place/SOUTH+AMERICANS+SECRETS+E.I.R.L/@-13.8313462,-76.2468435,20.28z",
    areaServed: "Paracas, Peru",
  };

  return (
    <>
      <Helmet>
        <html lang={lang} />
        <title>{t.metaTitle}</title>
        <meta name="description" content={t.metaDescription} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/home" />
        <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/home" />
        <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/home" />
        <meta property="og:title" content={t.metaTitle} />
        <meta property="og:description" content={t.metaDescription} />
        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonicalUrl} />
        <meta property="og:image" content="https://turismonauticoparacas.com/extras.png" />
        <meta property="og:locale" content={lang === "es" ? "es_PE" : "en_US"} />
        <meta name="twitter:card" content="summary_large_image" />
        <script type="application/ld+json">{JSON.stringify(jsonLd)}</script>
      </Helmet>
      {/* ================hero section start==================== */}
      <section className="home-home">
        {/*<div className="overlay"></div>{/*
        {/*<video src={heroVideo2} muted autoPlay loop type="video/mp4"></video>*/}
        <div className="slider-container">
          <div
            className="slider"
            style={{ transform: `translateX(-${currentIndex * 100}%)` }}
          >
            {sliderImages.map((img, idx) => (
              <img
                src={img}
                alt={`Tour en Paracas - vista ${idx + 1}`}
                key={idx}
              />
            ))}
          </div>
          {/* ✅ Indicadores de burbujas */}
          <div className="slider-dots">
            {sliderImages.map((_, index) => (
              <span
                key={index}
                className={`dot ${index === currentIndex ? "active" : ""}`}
                onClick={() => handleDotClick(index)}
              ></span>
            ))}
          </div>
        </div>
        <div className="homeContent container">
          <div className="textDiv">
            <span className="smallText">{t.smallText}</span>
            <h1 className="homeTitle">{t.heroTitle}</h1>
          </div>
        </div>
      </section>
      {/* <section>
        <Container>
          <Row>
            <Col lg="6">
                  <div className="hero__content">
                    <div className="hero__subtitle d-flex align-items-center">
                      <Subtitle subtitle={"Know Before You Go"} />
                      <img src={worldImg} alt="" />
                    </div>
                    <h1>
                      Turismo Nautico Paracas{""}
                      <span className="highlight"> south Peru</span>
                    </h1>
                    <p>
                      Fantastic tours and expert guides that help you make the most
                      of your trip to Peru!
                    </p>
                  </div>
              
            </Col>

            <Col lg="2">
              <div className="hero__img-box">
                <img src={heroImg} alt="" />
              </div>
            </Col>

            <Col lg="2">
              <div className="hero__img-box hero__video-box mt-4">
                <video src={heroVideo} alt="" autoPlay muted loop/>
              </div>
            </Col>

            <Col lg="2">
              <div className="hero__img-box mt-5">
                <img src={heroImg02} alt="" />
              </div>
            </Col>

            {/* <SearchBar /> 
          </Row>
        </Container>
      </section> */}
      {/* ================hero section start==================== */}
      {/*<section>
        <Container>
          <Row>
            <Col lg="3">
              <h5 className="services__subtitle">What we serve</h5>
              <h2 className="services__title">We offer our best services</h2>
            </Col>
            <ServiceList />
          </Row>
        </Container>
      </section> */}

      {/* ================featured section start==================== */}
      <section>
        <Container>
          <Row>
            <Col lg="12" className="mb-5">
              <Subtitle subtitle={t.explore} />
              <h2 className="featured__tour-title">{t.featuredTitle}</h2>
            </Col>
            <FeaturedTourList />
          </Row>
        </Container>
      </section>
      {/* ================featured section end==================== */}
      {/* ================ experience section start ==================== */}
      <section>
        <Container>
          <Row>
            <Col lg="6">
              <div className="experience__content">
                <Subtitle subtitle={t.sailWithUs} />

                <h2>{t.experienceTitle}</h2>
                <p>{t.experienceText}</p>
              </div>

              <div
                className="counter__wrapper d-flex align-items-center gap-5
                    "
              >
                <div className="counter__box">
                  <span>10k+</span>
                  <h6>{t.trips}</h6>
                </div>

                <div className="counter__box">
                  <span>4k+</span>
                  <h6>{t.clients}</h6>
                </div>

                <div className="counter__box">
                  <span>21</span>
                  <h6>{t.years}</h6>
                </div>
              </div>
            </Col>

            <Col lg="6">
              <div className="experience__img">
                <img src={experienceImg} alt="Tripulación de Turismo Nautico Paracas navegando" />
              </div>
            </Col>
          </Row>
        </Container>
      </section>
      {/* ================ experience section end ==================== */}

      {/* ================ gallery section start ==================== */}
      <section>
        <Container>
          <Row>
            <Col lg="12">
              <Subtitle subtitle={t.galleryLabel} />
              <h2 className="gallery_title">{t.galleryTitle}</h2>
            </Col>
            <Col lg="12">
              <MasonryImagesGallery />
            </Col>
          </Row>
        </Container>
      </section>
      {/* ================ gallery section end ==================== */}

      {/* ================ testimonial section start ==================== */}
      <section>
        <Container>
          <Row>
            <Col lg="12">
              <Subtitle subtitle={t.clientsLabel} />
              <h2 className="testimonial__title">{t.testimonialTitle}</h2>
            </Col>

            <Col lg="12">
              <Testimonial />
            </Col>
          </Row>
        </Container>
      </section>
      {/* ================ testimonial section end ==================== */}
      <Newsletter />
    </>
  );
};

export default Home;
