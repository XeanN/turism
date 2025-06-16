// src/components/Blogs/BlogCard.jsx
import React from "react";
import { Link } from "react-router-dom";
import "./blogs.css";

const BlogCard = ({ blog }) => {
  return (
    <div className="blog__card">
      <img src={blog.image} alt={blog.title} className="blog__image" />
      <div className="blog__meta">
        <span>{blog.date}</span>
        <span>{blog.author}</span>
        <span>{blog.category}</span>
      </div>
      <h3 className="blog__title">{blog.title}</h3>
      <p className="blog__summary">{blog.summary}</p>
      <Link to={`/blogs/${blog.slug}`} className="blog__btn">
        Read More
      </Link>
    </div>
  );
};

export default BlogCard;
