import React from "react";
import { Helmet } from "react-helmet";
import CommonSection from "../shared/CommonSection";
import { Container, Row, Col } from "reactstrap";
import BlogCard from "../components/Blogs/BlogCard";
import { blogs } from "../assets/data/blogs";
import "../styles/blogs.css";
import Newsletter from "../shared/Newsletter";
import { useLanguage } from "../context/LanguageContext";

const text = {
  en: {
    metaTitle: "Travel Blog | Turismo Nautico Paracas",
    metaDescription: "Guides and tips for your trip to Paracas: Ballestas Islands, National Reserve, sandboarding in Huacachina, Nazca Lines and more.",
    pageTitle: "Our travel blogs",
  },
  es: {
    metaTitle: "Blog de Viajes | Turismo Nautico Paracas",
    metaDescription: "Guías y consejos para tu viaje a Paracas: Islas Ballestas, Reserva Nacional, sandboarding en Huacachina, Líneas de Nazca y más.",
    pageTitle: "Nuestro Blog de Viajes",
  },
};

const Blogs = () => {
  const lang = useLanguage();
  const t = text[lang];
  const canonicalUrl = lang === "es"
    ? "https://turismonauticoparacas.com/es/blogs"
    : "https://turismonauticoparacas.com/blogs";

  return (
    <>
      <Helmet>
        <title>{t.metaTitle}</title>
        <meta name="description" content={t.metaDescription} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/blogs" />
        <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/blogs" />
        <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/blogs" />
        <meta property="og:title" content={t.metaTitle} />
        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonicalUrl} />
      </Helmet>
      <CommonSection title={t.pageTitle} />
      <section>
        <Container>
          <Row>
            {blogs.map((blog) => (
              <Col lg="4" md="6" sm="12" key={blog.id} className="mb-4">
                <BlogCard blog={blog} />
              </Col>
            ))}
          </Row>
        </Container>
      </section>
      <Newsletter />
    </>
  );
};

export default Blogs;
