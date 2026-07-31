// src/components/Blogs/BlogCard.jsx
import React from "react";
import { Link } from "react-router-dom";
import "./blogs.css";
import { useLanguage, withLang } from "../../context/LanguageContext";
import { getBlogText } from "../../assets/data/blogs";

const readMoreText = { en: "Read More", es: "Leer Más" };

const BlogCard = ({ blog }) => {
  const lang = useLanguage();
  const { title, summary, category } = getBlogText(blog, lang);

  return (
    <div className="blog__card">
      <img src={blog.image} alt={title} className="blog__image" />
      <div className="blog__meta">
        <span>{blog.date}</span>
        <span>{blog.author}</span>
        <span>{category}</span>
      </div>
      <h3 className="blog__title">{title}</h3>
      <p className="blog__summary">{summary}</p>
      <Link to={withLang(`/blogs/${blog.slug}`, lang)} className="blog__btn">
        {readMoreText[lang]}
      </Link>
    </div>
  );
};

export default BlogCard;
