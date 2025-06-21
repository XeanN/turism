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

const BlogDetails = () => {
  const { slug } = useParams();
  const blog = blogs.find((item) => item.slug === slug);

  const blogContentMap = {
    "que-ver-en-paracas-en-un-dia": <Blog1 />,
    "sandboarding-y-buggy-en-paracas": <Blog2 />,
    "reserva-nacional-de-paracas": <Blog3 />,
    "islas-ballestas-paracas": <Blog4 />,
    "tour-privado-en-paracas": <Blog5 />,
    "yacht-charter-en-paracas": <Blog6 />,
    "servicios-especiales-paracas": <Blog7 />,
    "lineas-de-nazca-desde-paracas": <Blog8 />,
    "fauna-marina-paracas": <Blog9 />,
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
