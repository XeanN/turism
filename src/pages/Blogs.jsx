import React from "react";
import CommonSection from "../shared/CommonSection";
import { Container, Row, Col } from "reactstrap";
import BlogCard from "../components/Blogs/BlogCard";
import { blogs } from "../assets/data/blogs";
import "../styles/blogs.css";
import Newsletter from "../shared/Newsletter";

const Blogs = () => {
  return (
    <>
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
