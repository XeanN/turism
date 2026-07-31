import React, { useState, useEffect } from "react";
import { Helmet } from "react-helmet";
import CommonSection from "../shared/CommonSection";

import "../styles/tours.css";
import TourCard from "./../shared/TourCard";
//import SearchBar from "./../shared/SearchBar";
import Newsletter from "./../shared/Newsletter";
import { Container, Row, Col } from "reactstrap";

import useFetch from "../hooks/useFetch";
import { BASE_URL } from "../utils/config";
import { useLanguage } from "../context/LanguageContext";

const text = {
  en: {
    metaTitle: "All Tours in Paracas | Turismo Nautico Paracas",
    metaDescription: "Discover all our tours in Paracas: Ballestas Islands, National Reserve, Nazca, private yachts and more. Book your adventure on the southern coast of Peru.",
    pageTitle: "All Tours",
    loading: "Loading.....",
    noTours: "No tours available.",
  },
  es: {
    metaTitle: "Todos los Tours en Paracas | Turismo Nautico Paracas",
    metaDescription: "Descubre todos nuestros tours en Paracas: Islas Ballestas, Reserva Nacional, Nazca, yates privados y más. Reserva tu aventura en la costa sur del Perú.",
    pageTitle: "Todos los Tours",
    loading: "Cargando.....",
    noTours: "No hay tours disponibles.",
  },
};

const Tours = () => {
  const lang = useLanguage();
  const t = text[lang];
  const canonicalUrl = lang === "es"
    ? "https://turismonauticoparacas.com/es/tours"
    : "https://turismonauticoparacas.com/tours";
  const [pageCount, setPageCount] = useState(0);
  const [page, setPage] = useState(0);

  const {
    data: tours,
    loading,
    error,
  } = useFetch(`${BASE_URL}/tour/getAllTours?page=${page}&limit=12`);
  const { data: tourCount } = useFetch(`${BASE_URL}/tour/getTotalTours`);

  useEffect(() => {
    if (tourCount > 0) {
      const pages = Math.ceil(tourCount / 12);
      setPageCount(pages);
    } else {
      setPageCount(0);
    }
    window.scrollTo(0, 0);
  }, [page, tourCount, tours]);

  return (
    <>
      <Helmet>
        <title>{t.metaTitle}</title>
        <meta name="description" content={t.metaDescription} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/tours" />
        <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/tours" />
        <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/tours" />
        <meta property="og:title" content={t.metaTitle} />
        <meta property="og:description" content={t.metaDescription} />
        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonicalUrl} />
      </Helmet>
      <CommonSection title={t.pageTitle} />
      <section>
        <Container>
          <Row>
            {/* <SearchBar /> */}
          </Row>
        </Container>
      </section>

      <section className="pt-0">
        <Container>
          {loading && <h4 className="text-center pt-5">{t.loading}</h4>}
          {error && <h4 className="text-center pt-5">{error}</h4>}
          {!loading && !error && (
            <Row>
              {tours.length > 0 ? (
                tours.map((tour) => (
                  <Col lg="3" md="6" sm="6" className="mb-4" key={tour.id}>
                    <TourCard tour={tour} />
                  </Col>
                ))
              ) : (
                <Col lg="12">
                  <p className="text-center">{t.noTours}</p>
                </Col>
              )}

              <Col lg="12">
                <div className="pagination d-flex align-items-center justify-content-center mt-4 gap-3">
                  {[...Array(pageCount).keys()].map((number) => (
                    <span
                      key={number}
                      onClick={() => setPage(number)}
                      className={page === number ? "active__page" : ""}
                    >
                      {number + 1}
                    </span>
                  ))}
                </div>
              </Col>
            </Row>
          )}
        </Container>
      </section>
      <Newsletter />
    </>
  );
};

export default Tours;
