import React from "react";
import { useParams } from "react-router-dom";
import { blogs } from "../assets/data/blogs";
import CommonSection from "../shared/CommonSection";
import { Helmet } from "react-helmet";
import { Container, Row, Col } from "reactstrap";
//import ReactMarkdown from "react-markdown";
//import remarkGfm from "remark-gfm";
import "../styles/blogs.css";
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

const BlogDetails = () => {
  const { slug } = useParams();
  const blog = blogs.find((item) => item.slug === slug);

  const blogContentMap = {
    "what-to-see-in-paracas-in-one-day": <Blog1 />,
    "sandboarding-and-buggy-in-paracas": <Blog2 />,
    "paracas-national-reserve": <Blog3 />,
    "ballestas-islands-paracas": <Blog4 />,
    "private-tour-in-paracas": <Blog5 />,
    "yacht-charter-in-paracas": <Blog6 />,
    "special-services-in-paracas": <Blog7 />,
    "nazca-lines-from-paracas": <Blog8 />,
    "marine-fauna-in-paracas": <Blog9 />,
    "nazca-lines-from-pisco": <Blog10 />,
    "montesierpe": <Blog11 />,
    "guano-collectors": <Blog12 />

  };

  if (!blog) {
    return <h2 className="text-center pt-5">Blog not found</h2>;
  }

  return (
    <>
      <Helmet>
        <title>{blog.title} | Turismo Náutico Paracas</title>
        <meta name="description" content={blog.summary} />
        <meta name="author" content={blog.author} />
        <meta name="keywords" content={blog.category} />
        <link
          rel="canonical"
          href={`https://turismonauticoparacas.com/blogs/${blog.slug}`}
        />
        <meta property="og:title" content={blog.title} />
        <meta property="og:description" content={blog.summary} />
        <meta property="og:type" content="article" />
        <meta
          property="og:url"
          content={`https://turismonauticoparacas.com/blogs/${blog.slug}`}
        />
        <meta
          property="og:image"
          content={`https://turismonauticoparacas.com${blog.image}`}
        />
        <meta name="twitter:card" content="summary_large_image" />
      </Helmet>

      <CommonSection title={blog.title} />

      <section className="blog__detail">
        <Container>
          <Row>
            <Col lg="12">
              <img src={blog.image} alt={blog.title} className="blog__image mb-4" />
              <div className="blog__meta">
                <span>{blog.date}</span>
                <span>{blog.author}</span>
                <span>{blog.category}</span>
              </div>
              <h3 className="blog__title mt-3">{blog.title}</h3>
              <p className="blog__summary">{blog.summary}</p>

              {blogContentMap[slug]}
            </Col>
          </Row>
        </Container>
      </section>
    </>
  );
};

export default BlogDetails;
