import React from "react";
import { useParams } from "react-router-dom";
import { blogs, getBlogText } from "../assets/data/blogs";
import CommonSection from "../shared/CommonSection";
import { Helmet } from "react-helmet";
import { Container, Row, Col } from "reactstrap";
//import ReactMarkdown from "react-markdown";
//import remarkGfm from "remark-gfm";
import "../styles/blogs.css";
import { useLanguage } from "../context/LanguageContext";
import Blog1 from "../pages/blogs/Que-ver-en-paracas-en-un-dia";
import Blog2 from "../pages/blogs/Sandboarding-y-buggy-en-paracas";
import Blog3 from "../pages/blogs/Reserva-nacional-de-paracas";
import Blog4 from "../pages/blogs/Islas-ballestas-paracas";
import Blog5 from "../pages/blogs/Tour-privado-en-paracas";
import Blog6 from "../pages/blogs/Yacht-charter-en-paracas";
import Blog7 from "../pages/blogs/Servicios-especiales-paracas";
import Blog8 from "../pages/blogs/Lineas-de-nazca-desde-paracas";
import Blog9 from "../pages/blogs/Fauna-marina-paracas";
import Blog10 from "../pages/blogs/Sobrevolando-las-líneas-de-Nazca-desde-Pisco";
import Blog11 from "../pages/blogs/Montesierpe";
import Blog12 from "../pages/blogs/Guano-collectors";

const notFoundText = { en: "Blog not found", es: "Artículo no encontrado" };

const BlogDetails = () => {
  const { slug } = useParams();
  const lang = useLanguage();
  const blog = blogs.find((item) => item.slug === slug);

  const blogContentMap = {
    "what-to-see-in-paracas-in-one-day": <Blog1 lang={lang} />,
    "sandboarding-and-buggy-in-paracas": <Blog2 lang={lang} />,
    "paracas-national-reserve": <Blog3 lang={lang} />,
    "ballestas-islands-paracas": <Blog4 lang={lang} />,
    "private-tour-in-paracas": <Blog5 lang={lang} />,
    "yacht-charter-in-paracas": <Blog6 lang={lang} />,
    "special-services-in-paracas": <Blog7 lang={lang} />,
    "nazca-lines-from-paracas": <Blog8 lang={lang} />,
    "marine-fauna-in-paracas": <Blog9 lang={lang} />,
    "nazca-lines-from-pisco": <Blog10 lang={lang} />,
    "montesierpe": <Blog11 lang={lang} />,
    "guano-collectors": <Blog12 lang={lang} />,
  };

  if (!blog) {
    return <h2 className="text-center pt-5">{notFoundText[lang]}</h2>;
  }

  const { title, summary, category } = getBlogText(blog, lang);
  const enUrl = `https://turismonauticoparacas.com/blogs/${blog.slug}`;
  const esUrl = `https://turismonauticoparacas.com/es/blogs/${blog.slug}`;
  const canonicalUrl = lang === "es" ? esUrl : enUrl;

  return (
    <>
      <Helmet>
        <title>{title} | Turismo Náutico Paracas</title>
        <meta name="description" content={summary} />
        <meta name="author" content={blog.author} />
        <meta name="keywords" content={category} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href={enUrl} />
        <link rel="alternate" hrefLang="es" href={esUrl} />
        <link rel="alternate" hrefLang="x-default" href={enUrl} />
        <meta property="og:title" content={title} />
        <meta property="og:description" content={summary} />
        <meta property="og:type" content="article" />
        <meta property="og:url" content={canonicalUrl} />
        <meta
          property="og:image"
          content={`https://turismonauticoparacas.com${blog.image}`}
        />
        <meta name="twitter:card" content="summary_large_image" />
      </Helmet>

      <CommonSection title={title} />

      <section className="blog__detail">
        <Container>
          <Row>
            <Col lg="12">
              <img src={blog.image} alt={title} className="blog__image mb-4" />
              <div className="blog__meta">
                <span>{blog.date}</span>
                <span>{blog.author}</span>
                <span>{category}</span>
              </div>
              <h3 className="blog__title mt-3">{title}</h3>
              <p className="blog__summary">{summary}</p>

              {blogContentMap[slug]}
            </Col>
          </Row>
        </Container>
      </section>
    </>
  );
};

export default BlogDetails;
