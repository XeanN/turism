import React from "react";
import CommonSection from "../shared/CommonSection";
import { Container, Row, Col } from "reactstrap";
import Newsletter from "../shared/Newsletter";
import { blogs } from "../assets/data/blogs";
import BlogCard from "../components/Blogs/BlogCard";

const Blogs = () => {
  return (
    <>
      <CommonSection title="Latest Blog Posts" />
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
