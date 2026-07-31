import React from "react";
import { Routes, Route } from "react-router-dom";

import Home from "./../pages/Home";
import Login from "./../pages/Login";
import Register from "./../pages/Register";
import SearchResultList from "./../pages/SearchResultList";
import TourDetails from "../pages/TourDetails";
import Tours from "./../pages/Tours";
import ThankYou from "../pages/ThankYou";
import About from "../pages/About";
import Blogs from "../pages/Blogs";
import BlogDetails from "../pages/BlogDetails";
import Contact from "../pages/Contact";
import Gallery from "../pages/Gallery";

// Mismas páginas para los dos idiomas: cada página lee el idioma actual
// con useLanguage() (provisto por Layout, a partir de la URL) y decide
// qué texto mostrar. El fetch al backend (BASE_URL/tour/..., etc.) es
// idéntico en ambos casos.
const AppRoutes = () => (
  <Routes>
    <Route path="/" element={<Home />} />
    <Route path="/home" element={<Home />} />
    <Route path="/tours" element={<Tours />} />
    <Route path="/tours/:slug" element={<TourDetails />} />
    <Route path="/login" element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/thank-you" element={<ThankYou />} />
    <Route path="/tours/search" element={<SearchResultList />} />
    <Route path="/about" element={<About />} />
    <Route path="/blogs" element={<Blogs />} />
    <Route path="/blogs/:slug" element={<BlogDetails />} />
    <Route path="/contact" element={<Contact />} />
    <Route path="/gallery" element={<Gallery />} />
  </Routes>
);

const Routers = () => {
  return (
    <Routes>
      <Route path="/es/*" element={<AppRoutes />} />
      <Route path="/*" element={<AppRoutes />} />
    </Routes>
  );
};

export default Routers;
