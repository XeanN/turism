import React from "react";
import { Helmet } from "react-helmet";
import CommonSection from "../shared/CommonSection";
import { Container, Row, Col } from "reactstrap";
import BlogCard from "../components/Blogs/BlogCard";
import { blogs } from "../assets/data/blogs";
import "../styles/blogs.css";
import Newsletter from "../shared/Newsletter";

const Blogs = () => {
  return (
    <>
      <Helmet>
        <title>Blog de Viajes | Turismo Nautico Paracas</title>
        <meta
          name="description"
          content="Guías y consejos para tu viaje a Paracas: Islas Ballestas, Reserva Nacional, sandboarding en Huacachina, Líneas de Nazca y más."
        />
        <link rel="canonical" href="https://turismonauticoparacas.com/blogs" />
        <meta property="og:title" content="Blog de Viajes - Turismo Nautico Paracas" />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://turismonauticoparacas.com/blogs" />
      </Helmet>
      <CommonSection title="Our travel blogs" />
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
