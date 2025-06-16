
import React from "react";
import { useParams } from "react-router-dom";
import { blogs } from "../assets/data/blogs";
import CommonSection from "../shared/CommonSection";
import { Helmet } from "react-helmet";
import { Container, Row, Col } from "reactstrap";
import "../styles/blogs.css";

const BlogDetails = () => {
  const { slug } = useParams();
  const blog = blogs.find((item) => item.slug === slug);

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
              <p className="blog__body mt-4">
               
                Bienvenido a nuestro blog sobre {blog.title}. En este artículo te mostraremos los mejores lugares para visitar, consejos prácticos, datos históricos y más sobre esta experiencia en Paracas/Nazca/Ica. 
                <br /><br />
                Próximamente, se podrá integrar contenido dinámico desde una base de datos o CMS.
              </p>
            </Col>
          </Row>
        </Container>
      </section>
    </>
  );
};

export default BlogDetails;
